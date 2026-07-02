// Package management provides a REST client for Hilt's tenant and access-key
// management API (the handlers in pkg/api). It authenticates with the partner
// key as an HTTP bearer token and speaks plain JSON — it is not a UCAN client
// (cf. the UCAN clients in the parent pkg/client package).
package management

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/fil-forge/hilt/pkg/api"
	"go.uber.org/zap"
)

// Option configures a [Client].
type Option func(*config)

type config struct {
	httpClient *http.Client
	logger     *zap.Logger
}

// WithHTTPClient sets the HTTP client used for requests. A nil client is
// ignored (the default [http.DefaultClient] is kept).
func WithHTTPClient(httpClient *http.Client) Option {
	return func(cfg *config) {
		if httpClient != nil {
			cfg.httpClient = httpClient
		}
	}
}

// WithLogger sets the logger. A nil logger is ignored (a no-op logger is kept).
func WithLogger(logger *zap.Logger) Option {
	return func(cfg *config) {
		if logger != nil {
			cfg.logger = logger
		}
	}
}

// Client is a REST client for the Hilt management API.
type Client struct {
	baseURL    url.URL
	partnerKey string
	httpClient *http.Client
	logger     *zap.Logger
}

// NewClient creates a management API client that targets baseURL and
// authenticates with partnerKey (sent as "Authorization: Bearer <partnerKey>").
func NewClient(baseURL url.URL, partnerKey string, opts ...Option) *Client {
	cfg := &config{httpClient: http.DefaultClient, logger: zap.NewNop()}
	for _, opt := range opts {
		opt(cfg)
	}
	return &Client{
		baseURL:    baseURL,
		partnerKey: partnerKey,
		httpClient: cfg.httpClient,
		logger:     cfg.logger,
	}
}

// APIError is returned when the server responds with an unexpected status code.
// It carries the HTTP status and the server's error message so callers can
// branch on the status (e.g. 404 Not Found, 409 Conflict).
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("management: unexpected status %d", e.StatusCode)
	}
	return fmt.Sprintf("management: status %d: %s", e.StatusCode, e.Message)
}

// Tenants

// ProvisionTenant provisions (or, idempotently, returns) the tenant with the
// given external id.
func (c *Client) ProvisionTenant(ctx context.Context, tenantID string, req api.ProvisionTenantRequest) (api.Tenant, error) {
	var t api.Tenant
	err := c.do(ctx, http.MethodPut, []string{"tenants", tenantID}, req, &t, http.StatusOK, http.StatusCreated)
	return t, err
}

// GetTenant retrieves the tenant with the given external id.
func (c *Client) GetTenant(ctx context.Context, tenantID string) (api.Tenant, error) {
	var t api.Tenant
	err := c.do(ctx, http.MethodGet, []string{"tenants", tenantID}, nil, &t, http.StatusOK)
	return t, err
}

// UpdateTenantStatus updates the access mode of the tenant.
func (c *Client) UpdateTenantStatus(ctx context.Context, tenantID string, status api.TenantStatus) error {
	return c.do(ctx, http.MethodPost, []string{"tenants", tenantID, "status"},
		api.UpdateTenantStatusRequest{Status: status}, nil, http.StatusNoContent)
}

// DeleteTenant permanently deletes the tenant. It is idempotent server-side.
func (c *Client) DeleteTenant(ctx context.Context, tenantID string) error {
	return c.do(ctx, http.MethodDelete, []string{"tenants", tenantID}, nil, nil, http.StatusNoContent)
}

// Access keys

// CreateAccessKey creates an S3 access key for the tenant. The returned
// [api.CreatedAccessKey] is the only time the secret access key is exposed.
func (c *Client) CreateAccessKey(ctx context.Context, tenantID string, req api.CreateAccessKeyRequest) (api.CreatedAccessKey, error) {
	var k api.CreatedAccessKey
	err := c.do(ctx, http.MethodPost, []string{"tenants", tenantID, "access-keys"}, req, &k, http.StatusCreated)
	return k, err
}

// ListAccessKeys lists the tenant's access keys (secrets are never included).
func (c *Client) ListAccessKeys(ctx context.Context, tenantID string) ([]api.AccessKey, error) {
	var list api.AccessKeyList
	err := c.do(ctx, http.MethodGet, []string{"tenants", tenantID, "access-keys"}, nil, &list, http.StatusOK)
	return list.Items, err
}

// GetAccessKey retrieves metadata for a single access key.
func (c *Client) GetAccessKey(ctx context.Context, tenantID, accessKeyID string) (api.AccessKey, error) {
	var k api.AccessKey
	err := c.do(ctx, http.MethodGet, []string{"tenants", tenantID, "access-keys", accessKeyID}, nil, &k, http.StatusOK)
	return k, err
}

// DeleteAccessKey revokes an access key. It is idempotent server-side.
func (c *Client) DeleteAccessKey(ctx context.Context, tenantID, accessKeyID string) error {
	return c.do(ctx, http.MethodDelete, []string{"tenants", tenantID, "access-keys", accessKeyID}, nil, nil, http.StatusNoContent)
}

// do executes a single request: it builds the URL from path segments (JoinPath
// escapes them), sets auth/JSON headers, sends the (optional) JSON body, checks
// the status against wantStatus, and decodes the response into out when non-nil.
func (c *Client) do(ctx context.Context, method string, segments []string, body, out any, wantStatus ...int) error {
	u := c.baseURL.JoinPath(segments...)

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.partnerKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	c.logger.Debug("executing management request", zap.String("method", method), zap.String("url", u.String()))
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing %s %s: %w", method, u.String(), err)
	}
	defer resp.Body.Close()

	if !slices.Contains(wantStatus, resp.StatusCode) {
		return apiErrorFromResponse(resp)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

// apiErrorFromResponse builds an [APIError] from a non-2xx response, reading the
// echo default error shape ({"message": "..."}) and falling back to the raw body.
func apiErrorFromResponse(resp *http.Response) error {
	apiErr := &APIError{StatusCode: resp.StatusCode}
	data, _ := io.ReadAll(resp.Body)
	var envelope struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.Message != "" {
		apiErr.Message = envelope.Message
	} else {
		apiErr.Message = strings.TrimSpace(string(data))
	}
	return apiErr
}
