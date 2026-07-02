package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

const bearerPrefix = "Bearer "

// PartnerKeyAuth returns echo middleware that requires requests to carry the
// configured partner key as an HTTP bearer token
// (Authorization: Bearer <partnerKey>). It responds 401 when the header is
// missing, malformed, or does not match. If partnerKey is empty (unconfigured),
// it fails closed and rejects all requests. The key and presented token are
// never logged.
func PartnerKeyAuth(partnerKey []string, logger *zap.Logger) echo.MiddlewareFunc {
	// normalize the key set
	var keys []string
	for _, k := range partnerKey {
		if strings.TrimSpace(k) != "" {
			keys = append(keys, k)
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if len(keys) == 0 {
				logger.Warn("partner key not configured; rejecting request")
				return unauthorized(c)
			}

			auth := c.Request().Header.Get(echo.HeaderAuthorization)
			if len(auth) <= len(bearerPrefix) || !strings.EqualFold(auth[:len(bearerPrefix)], bearerPrefix) {
				logger.Debug("missing or malformed Authorization header")
				return unauthorized(c)
			}
			token := auth[len(bearerPrefix):]

			valid := false
			for _, key := range keys {
				if subtle.ConstantTimeCompare([]byte(token), []byte(key)) == 1 {
					valid = true
					break
				}
			}
			if !valid {
				logger.Debug("partner key mismatch")
				return unauthorized(c)
			}

			return next(c)
		}
	}
}

func unauthorized(c echo.Context) error {
	c.Response().Header().Set(echo.HeaderWWWAuthenticate, "Bearer")
	return echo.NewHTTPError(http.StatusUnauthorized, "invalid or missing partner key")
}
