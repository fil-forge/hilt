package api

import (
	"errors"

	ucanerrors "github.com/fil-forge/ucantone/errors"
	"github.com/labstack/echo/v4"
)

// Error is the body of every Tenant API error response: a human-readable
// message and, for the errors the services name, a stable machine-readable code
// clients can branch on instead of parsing the message.
type Error struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

// httpError builds an echo HTTP error carrying err as an [Error] body. The code
// is the stable Name() of the service error, found by unwrapping, so an error
// wrapped with extra context still reports its sentinel's name. An error that
// carries no name is returned with its message alone.
func httpError(status int, err error) *echo.HTTPError {
	body := Error{Message: err.Error()}
	var named ucanerrors.Named
	if errors.As(err, &named) {
		body.Code = named.Name()
	}
	return echo.NewHTTPError(status, body)
}
