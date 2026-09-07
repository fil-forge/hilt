// Package openbao provides an OpenBao (KV v2) backed implementation of
// vault.Vault, using github.com/openbao/openbao/api/v2.
package openbao

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	hiltvault "github.com/fil-forge/hilt/pkg/vault"
	api "github.com/openbao/openbao/api/v2"
)

// dataKey is the field within a KV v2 secret under which the (base64-encoded)
// value bytes are stored. KV v2 data is JSON, so binary key material is
// base64-encoded.
const dataKey = "value"

// Store is a vault.Vault backed by an OpenBao KV v2 secrets engine.
type Store struct {
	client *api.Client
	mount  string

	// reauth logs the client in again and installs the new token. When set, an
	// operation rejected with 403 is retried once after a re-login. nil
	// disables the retry (static tokens cannot be refreshed).
	reauth func(context.Context) error

	// loginMu and loginGen make concurrent re-logins single-flight: callers
	// that observed the same generation share one login.
	loginMu  sync.Mutex
	loginGen uint64
}

var _ hiltvault.Vault = (*Store)(nil)

// New returns a Store that stores secrets in the KV v2 engine mounted at mount
// (e.g. "secret") using the given client. reauth, when non-nil, is called to
// log in again after OpenBao rejects the client's token with 403 Forbidden;
// the failed operation is then retried once.
func New(client *api.Client, mount string, reauth func(context.Context) error) *Store {
	return &Store{client: client, mount: mount, reauth: reauth}
}

func (s *Store) Read(ctx context.Context, key string) ([]byte, error) {
	var secret *api.KVSecret
	err := s.withReauth(ctx, func() error {
		var err error
		secret, err = s.kv().Get(ctx, secretPath(key))
		return err
	})
	if err != nil {
		if errors.Is(err, api.ErrSecretNotFound) {
			return nil, hiltvault.ErrNotFound
		}
		return nil, fmt.Errorf("reading secret: %w", err)
	}
	// A soft-deleted secret reads back with nil data.
	if secret.Data == nil {
		return nil, hiltvault.ErrNotFound
	}
	encoded, ok := secret.Data[dataKey].(string)
	if !ok {
		return nil, fmt.Errorf("secret missing %q field", dataKey)
	}
	value, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding secret value: %w", err)
	}
	return value, nil
}

func (s *Store) Write(ctx context.Context, key string, value []byte) error {
	err := s.withReauth(ctx, func() error {
		_, err := s.kv().Put(ctx, secretPath(key), map[string]any{
			dataKey: base64.StdEncoding.EncodeToString(value),
		})
		return err
	})
	if err != nil {
		return fmt.Errorf("writing secret: %w", err)
	}
	return nil
}

func (s *Store) Delete(ctx context.Context, key string) error {
	// Permanently remove the secret (all versions + metadata). Idempotent: a
	// missing secret is not an error, OpenBao answers the delete with 204.
	err := s.withReauth(ctx, func() error {
		return s.kv().DeleteMetadata(ctx, secretPath(key))
	})
	if err != nil {
		return fmt.Errorf("deleting secret: %w", err)
	}
	return nil
}

func (s *Store) kv() *api.KVv2 {
	return s.client.KVv2(s.mount)
}

// withReauth runs op. If op fails with 403 Forbidden and a reauth function is
// configured, it logs in again and runs op one more time. A second 403 is
// returned as is: it means the new token genuinely lacks permission, and
// looping would not help.
func (s *Store) withReauth(ctx context.Context, op func() error) error {
	gen := s.currentLoginGen()
	err := op()
	if err == nil || s.reauth == nil || !isStatus(err, http.StatusForbidden) {
		return err
	}
	if loginErr := s.reauthOnce(ctx, gen); loginErr != nil {
		return fmt.Errorf("%w; re-login after 403 failed: %w", err, loginErr)
	}
	return op()
}

func (s *Store) currentLoginGen() uint64 {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	return s.loginGen
}

// reauthOnce logs in again unless another caller already did so since the
// caller observed generation seenGen, in which case the fresh token is
// already installed and the caller just retries.
func (s *Store) reauthOnce(ctx context.Context, seenGen uint64) error {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	if s.loginGen != seenGen {
		return nil
	}
	if err := s.reauth(ctx); err != nil {
		return err
	}
	s.loginGen++
	return nil
}

// isStatus reports whether err is an OpenBao API error carrying the given HTTP
// status code.
func isStatus(err error, status int) bool {
	var respErr *api.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == status
}

// secretPath normalizes a vault key into a KV v2 secret path. Hilt keys are
// path-like (e.g. "/tenant/{id}"); a leading slash would create an empty path
// segment in the OpenBao API URL, so it is trimmed.
func secretPath(key string) string {
	return strings.TrimPrefix(key, "/")
}
