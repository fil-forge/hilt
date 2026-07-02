// Package hashicorp provides a HashiCorp Vault (KV v2) backed implementation of
// vault.Vault, using github.com/hashicorp/vault-client-go.
package hashicorp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	hiltvault "github.com/fil-forge/hilt/pkg/vault"
	vaultclient "github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

// dataKey is the field within a KV v2 secret under which the (base64-encoded)
// value bytes are stored. KV v2 data is JSON, so binary key material is
// base64-encoded.
const dataKey = "value"

// Store is a vault.Vault backed by a HashiCorp Vault KV v2 secrets engine.
type Store struct {
	client *vaultclient.Client
	mount  string
}

var _ hiltvault.Vault = (*Store)(nil)

// New returns a Store that stores secrets in the KV v2 engine mounted at mount
// (e.g. "secret") using the given client.
func New(client *vaultclient.Client, mount string) *Store {
	return &Store{client: client, mount: mount}
}

func (s *Store) Read(ctx context.Context, key string) ([]byte, error) {
	resp, err := s.client.Secrets.KvV2Read(ctx, secretPath(key), vaultclient.WithMountPath(s.mount))
	if err != nil {
		if vaultclient.IsErrorStatus(err, http.StatusNotFound) {
			return nil, hiltvault.ErrNotFound
		}
		return nil, fmt.Errorf("reading secret: %w", err)
	}
	// A soft-deleted secret reads back with nil data.
	if resp.Data.Data == nil {
		return nil, hiltvault.ErrNotFound
	}
	encoded, ok := resp.Data.Data[dataKey].(string)
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
	_, err := s.client.Secrets.KvV2Write(ctx, secretPath(key), schema.KvV2WriteRequest{
		Data: map[string]any{
			dataKey: base64.StdEncoding.EncodeToString(value),
		},
	}, vaultclient.WithMountPath(s.mount))
	if err != nil {
		return fmt.Errorf("writing secret: %w", err)
	}
	return nil
}

func (s *Store) Delete(ctx context.Context, key string) error {
	// Permanently remove the secret (all versions + metadata). Idempotent: a
	// missing secret is not an error.
	_, err := s.client.Secrets.KvV2DeleteMetadataAndAllVersions(ctx, secretPath(key), vaultclient.WithMountPath(s.mount))
	if err != nil {
		if vaultclient.IsErrorStatus(err, http.StatusNotFound) {
			return nil
		}
		return fmt.Errorf("deleting secret: %w", err)
	}
	return nil
}

// secretPath normalizes a vault key into a KV v2 secret path. Hilt keys are
// path-like (e.g. "/tenant/{id}"); a leading slash would create an empty path
// segment in the Vault API URL, so it is trimmed.
func secretPath(key string) string {
	return strings.TrimPrefix(key, "/")
}
