// Package management provides a REST client for Hilt's tenant, principal,
// access-key and bucket policy management API (the handlers in pkg/api). It
// authenticates with the partner
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

// Principals

// CreatePrincipal records a principal of the tenant. It is idempotent: a
// principal that already exists is returned unchanged.
func (c *Client) CreatePrincipal(ctx context.Context, tenantID, userID string) (api.Principal, error) {
	var p api.Principal
	err := c.do(ctx, http.MethodPut, []string{"tenants", tenantID, "principals", userID}, nil, &p,
		http.StatusOK, http.StatusCreated)
	return p, err
}

// ListPrincipals lists the tenant's principals.
func (c *Client) ListPrincipals(ctx context.Context, tenantID string) ([]api.Principal, error) {
	var list api.PrincipalList
	err := c.do(ctx, http.MethodGet, []string{"tenants", tenantID, "principals"}, nil, &list, http.StatusOK)
	return list.Items, err
}

// GetPrincipal retrieves one principal of the tenant.
func (c *Client) GetPrincipal(ctx context.Context, tenantID, userID string) (api.Principal, error) {
	var p api.Principal
	err := c.do(ctx, http.MethodGet, []string{"tenants", tenantID, "principals", userID}, nil, &p, http.StatusOK)
	return p, err
}

// DeletePrincipal removes the principal, its access to every bucket, and its
// access keys. It is idempotent server-side.
func (c *Client) DeletePrincipal(ctx context.Context, tenantID, userID string) error {
	return c.do(ctx, http.MethodDelete, []string{"tenants", tenantID, "principals", userID}, nil, nil, http.StatusNoContent)
}

// ListPrincipalAccessKeys lists the keys bound to the principal (secrets are
// never included).
func (c *Client) ListPrincipalAccessKeys(ctx context.Context, tenantID, userID string) ([]api.AccessKey, error) {
	var list api.AccessKeyList
	err := c.do(ctx, http.MethodGet, []string{"tenants", tenantID, "principals", userID, "access-keys"}, nil, &list, http.StatusOK)
	return list.Items, err
}

// Bucket policies

// ErrMissingETag is returned when a policy read gives no ETag, which the
// compare-and-set writes have nothing to condition on.
var ErrMissingETag = fmt.Errorf("management: response carried no ETag")

// GetBucketPolicy reads the bucket's policy and the strong ETag its next write
// must carry. A bucket with no policy is a 404 [APIError].
func (c *Client) GetBucketPolicy(ctx context.Context, tenantID, bucketName string) (api.BucketPolicy, string, error) {
	var doc api.BucketPolicy
	header, err := c.doWithHeaders(ctx, http.MethodGet,
		[]string{"tenants", tenantID, "buckets", bucketName, "policy"}, nil, nil, &doc, http.StatusOK)
	if err != nil {
		return api.BucketPolicy{}, "", err
	}
	etag := header.Get("ETag")
	if etag == "" {
		return api.BucketPolicy{}, "", ErrMissingETag
	}
	return doc, etag, nil
}

// CreateBucketPolicy writes the bucket's first policy, conditioned on the
// bucket having none (If-None-Match: *). It returns the new ETag. A bucket
// that already has a policy is a 412 [APIError].
func (c *Client) CreateBucketPolicy(ctx context.Context, tenantID, bucketName string, doc api.BucketPolicy) (string, error) {
	return c.putBucketPolicy(ctx, tenantID, bucketName, doc,
		map[string]string{"If-None-Match": "*"}, http.StatusCreated)
}

// ReplaceBucketPolicy replaces the bucket's policy, conditioned on ifMatch
// being its current ETag. It returns the new ETag. A stale tag is a 412
// [APIError].
func (c *Client) ReplaceBucketPolicy(ctx context.Context, tenantID, bucketName string, doc api.BucketPolicy, ifMatch string) (string, error) {
	return c.putBucketPolicy(ctx, tenantID, bucketName, doc,
		map[string]string{"If-Match": ifMatch}, http.StatusOK)
}

func (c *Client) putBucketPolicy(ctx context.Context, tenantID, bucketName string, doc api.BucketPolicy, headers map[string]string, wantStatus int) (string, error) {
	header, err := c.doWithHeaders(ctx, http.MethodPut,
		[]string{"tenants", tenantID, "buckets", bucketName, "policy"}, headers, doc, nil, wantStatus)
	if err != nil {
		return "", err
	}
	etag := header.Get("ETag")
	if etag == "" {
		return "", ErrMissingETag
	}
	return etag, nil
}

// DeleteBucketPolicy removes the bucket's policy, conditioned on ifMatch being
// its current ETag.
func (c *Client) DeleteBucketPolicy(ctx context.Context, tenantID, bucketName, ifMatch string) error {
	_, err := c.doWithHeaders(ctx, http.MethodDelete,
		[]string{"tenants", tenantID, "buckets", bucketName, "policy"},
		map[string]string{"If-Match": ifMatch}, nil, nil, http.StatusNoContent)
	return err
}

// ListPrincipalPolicies lists every policy of the tenant with a statement
// naming the principal or the wildcard.
func (c *Client) ListPrincipalPolicies(ctx context.Context, tenantID, userID string) ([]api.PrincipalPolicy, error) {
	var list api.PrincipalPolicyList
	err := c.do(ctx, http.MethodGet, []string{"tenants", tenantID, "principals", userID, "policies"}, nil, &list, http.StatusOK)
	return list.Items, err
}

// GetPrincipalAccess returns the principal's effective actions per bucket.
// Buckets it has no action on are omitted.
func (c *Client) GetPrincipalAccess(ctx context.Context, tenantID, userID string) ([]api.BucketAccess, error) {
	var access api.PrincipalAccess
	err := c.do(ctx, http.MethodGet, []string{"tenants", tenantID, "principals", userID, "access"}, nil, &access, http.StatusOK)
	return access.Buckets, err
}

// do executes a single request and discards the response headers. See
// [Client.doWithHeaders].
func (c *Client) do(ctx context.Context, method string, segments []string, body, out any, wantStatus ...int) error {
	_, err := c.doWithHeaders(ctx, method, segments, nil, body, out, wantStatus...)
	return err
}

// doWithHeaders executes a single request: it builds the URL from path segments
// (JoinPath escapes them), sets auth/JSON headers plus any extra ones, sends
// the (optional) JSON body, checks the status against wantStatus, decodes the
// response into out when non-nil, and returns the response headers.
func (c *Client) doWithHeaders(ctx context.Context, method string, segments []string, headers map[string]string, body, out any, wantStatus ...int) (http.Header, error) {
	u := c.baseURL.JoinPath(segments...)

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), reqBody)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.partnerKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	c.logger.Debug("executing management request", zap.String("method", method), zap.String("url", u.String()))
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing %s %s: %w", method, u.String(), err)
	}
	defer resp.Body.Close()

	if !slices.Contains(wantStatus, resp.StatusCode) {
		return nil, apiErrorFromResponse(resp)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return nil, fmt.Errorf("decoding response: %w", err)
		}
	}
	return resp.Header, nil
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
