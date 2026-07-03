package management_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/fil-forge/hilt/pkg/api"
	"github.com/fil-forge/hilt/pkg/client/management"
	"github.com/stretchr/testify/require"
)

const testPartnerKey = "secret-partner-key"

// newClient builds a client pointed at an httptest server whose handler is fn.
// fn should assert the request and write the canned response.
func newClient(t *testing.T, fn http.HandlerFunc) *management.Client {
	t.Helper()
	srv := httptest.NewServer(fn)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return management.NewClient(*u, testPartnerKey, management.WithHTTPClient(srv.Client()))
}

// assertAuth checks the partner-key bearer header is present.
func assertAuth(t *testing.T, r *http.Request) {
	t.Helper()
	require.Equal(t, "Bearer "+testPartnerKey, r.Header.Get("Authorization"))
}

func TestManagementClient(t *testing.T) {
	ctx := context.Background()

	t.Run("ProvisionTenant returns the created tenant (201)", func(t *testing.T) {
		c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
			assertAuth(t, r)
			require.Equal(t, http.MethodPut, r.Method)
			require.Equal(t, "/tenants/acme", r.URL.Path)
			var body api.ProvisionTenantRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			require.Equal(t, "us-east-1", body.Region)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(api.Tenant{TenantID: "acme", Status: api.TenantStatusActive})
		})
		got, err := c.ProvisionTenant(ctx, "acme", api.ProvisionTenantRequest{Region: "us-east-1"})
		require.NoError(t, err)
		require.Equal(t, "acme", got.TenantID)
		require.Equal(t, api.TenantStatusActive, got.Status)
	})

	t.Run("ProvisionTenant accepts idempotent 200", func(t *testing.T) {
		c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(api.Tenant{TenantID: "acme"})
		})
		got, err := c.ProvisionTenant(ctx, "acme", api.ProvisionTenantRequest{Region: "us-east-1"})
		require.NoError(t, err)
		require.Equal(t, "acme", got.TenantID)
	})

	t.Run("GetTenant decodes the tenant", func(t *testing.T) {
		c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
			assertAuth(t, r)
			require.Equal(t, http.MethodGet, r.Method)
			require.Equal(t, "/tenants/acme", r.URL.Path)
			_ = json.NewEncoder(w).Encode(api.Tenant{TenantID: "acme", Status: api.TenantStatusWriteLocked})
		})
		got, err := c.GetTenant(ctx, "acme")
		require.NoError(t, err)
		require.Equal(t, api.TenantStatusWriteLocked, got.Status)
	})

	t.Run("UpdateTenantStatus sends the status and expects 204", func(t *testing.T) {
		c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
			assertAuth(t, r)
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "/tenants/acme/status", r.URL.Path)
			var body api.UpdateTenantStatusRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			require.Equal(t, api.TenantStatusDisabled, body.Status)
			w.WriteHeader(http.StatusNoContent)
		})
		require.NoError(t, c.UpdateTenantStatus(ctx, "acme", api.TenantStatusDisabled))
	})

	t.Run("DeleteTenant expects 204", func(t *testing.T) {
		c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
			assertAuth(t, r)
			require.Equal(t, http.MethodDelete, r.Method)
			require.Equal(t, "/tenants/acme", r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		})
		require.NoError(t, c.DeleteTenant(ctx, "acme"))
	})

	t.Run("CreateAccessKey returns the secret (201)", func(t *testing.T) {
		expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
		c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
			assertAuth(t, r)
			require.Equal(t, http.MethodPost, r.Method)
			require.Equal(t, "/tenants/acme/access-keys", r.URL.Path)
			var body api.CreateAccessKeyRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			require.Equal(t, "ci", body.Name)
			require.Equal(t, []string{"s3:GetObject"}, body.Permissions)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(api.CreatedAccessKey{
				AccessKey:       api.AccessKey{AccessKeyID: "AKID", Name: "ci", ExpiresAt: &expires},
				SecretAccessKey: "SECRET",
			})
		})
		got, err := c.CreateAccessKey(ctx, "acme", api.CreateAccessKeyRequest{Name: "ci", Permissions: []string{"s3:GetObject"}})
		require.NoError(t, err)
		require.Equal(t, "AKID", got.AccessKeyID)
		require.Equal(t, "SECRET", got.SecretAccessKey)
		require.NotNil(t, got.ExpiresAt)
	})

	t.Run("ListAccessKeys returns the items", func(t *testing.T) {
		c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
			assertAuth(t, r)
			require.Equal(t, http.MethodGet, r.Method)
			require.Equal(t, "/tenants/acme/access-keys", r.URL.Path)
			_ = json.NewEncoder(w).Encode(api.AccessKeyList{Items: []api.AccessKey{{AccessKeyID: "a"}, {AccessKeyID: "b"}}})
		})
		got, err := c.ListAccessKeys(ctx, "acme")
		require.NoError(t, err)
		require.Len(t, got, 2)
		require.Equal(t, "a", got[0].AccessKeyID)
	})

	t.Run("GetAccessKey decodes the key", func(t *testing.T) {
		c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
			assertAuth(t, r)
			require.Equal(t, http.MethodGet, r.Method)
			require.Equal(t, "/tenants/acme/access-keys/AKID", r.URL.Path)
			_ = json.NewEncoder(w).Encode(api.AccessKey{AccessKeyID: "AKID", Name: "ci"})
		})
		got, err := c.GetAccessKey(ctx, "acme", "AKID")
		require.NoError(t, err)
		require.Equal(t, "ci", got.Name)
	})

	t.Run("DeleteAccessKey expects 204", func(t *testing.T) {
		c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
			assertAuth(t, r)
			require.Equal(t, http.MethodDelete, r.Method)
			require.Equal(t, "/tenants/acme/access-keys/AKID", r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		})
		require.NoError(t, c.DeleteAccessKey(ctx, "acme", "AKID"))
	})

	t.Run("non-2xx returns an APIError carrying status and message", func(t *testing.T) {
		c := newClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"message": "tenant not found"})
		})
		_, err := c.GetTenant(ctx, "missing")
		require.Error(t, err)
		var apiErr *management.APIError
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, http.StatusNotFound, apiErr.StatusCode)
		require.Equal(t, "tenant not found", apiErr.Message)
	})

	t.Run("transport error is surfaced", func(t *testing.T) {
		u, err := url.Parse("http://management.test")
		require.NoError(t, err)
		c := management.NewClient(*u, testPartnerKey,
			management.WithHTTPClient(&http.Client{Transport: errRoundTripper{}}))
		_, err = c.GetTenant(ctx, "acme")
		require.Error(t, err)
	})
}

type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("transport boom")
}
