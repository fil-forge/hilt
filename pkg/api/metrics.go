package api

import (
	"errors"
	"net/http"
	"time"

	metricssvc "github.com/fil-forge/hilt/pkg/api/service/metrics"
	metricscmds "github.com/fil-forge/libforge/commands/metrics"
	ucanerrors "github.com/fil-forge/ucantone/errors"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// metricsHTTPError maps a metrics-service error to an echo HTTP error. Known
// errors (see the metrics service's errors.go) become their mapped status with
// the error's own message and code; anything else is logged and returned as a
// 500.
//
// The upload service names its own failures and they arrive here intact, so they
// are matched by name: a request it cannot serve is the caller's to fix, while
// one it could not serve just now is worth retrying.
func metricsHTTPError(log *zap.Logger, err error) error {
	switch {
	case errors.Is(err, metricssvc.ErrTenantNotFound), errors.Is(err, metricssvc.ErrBucketNotFound):
		return httpError(http.StatusNotFound, err)
	case errors.Is(err, metricssvc.ErrInvalidRange), errors.Is(err, metricssvc.ErrInvalidWindow):
		return httpError(http.StatusBadRequest, err)
	}

	var named ucanerrors.Named
	if errors.As(err, &named) {
		switch named.Name() {
		case metricscmds.InvalidRangeErrorName,
			metricscmds.InvalidWindowErrorName,
			metricscmds.TooManySamplesErrorName:
			return httpError(http.StatusBadRequest, err)
		case metricscmds.UsageUnstableErrorName, metricscmds.RangeTooBusyErrorName:
			return httpError(http.StatusServiceUnavailable, err)
		}
	}

	log.Error("request failed", zap.Error(err))
	return echo.NewHTTPError(http.StatusInternalServerError, "internal error")
}

// NewGetTenantMetricsHandler handles GET /tenants/{tenantId}/metrics — the
// tenant's usage over a range of time, summed across its buckets.
func NewGetTenantMetricsHandler(logger *zap.Logger, metrics *metricssvc.Service) Route {
	log := logger.With(zap.String("handler", "GetTenantMetrics"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/metrics", func(c echo.Context) error {
		from, to, window, err := metricsQuery(c)
		if err != nil {
			return metricsHTTPError(log, err)
		}
		samples, err := metrics.Tenant(c.Request().Context(), c.Param("tenantId"), from, to, window)
		if err != nil {
			return metricsHTTPError(log, err)
		}
		return c.JSON(http.StatusOK, metricsResponse(samples))
	})
}

// NewGetBucketMetricsHandler handles
// GET /tenants/{tenantId}/buckets/{bucketName}/metrics — one bucket's usage over
// a range of time.
func NewGetBucketMetricsHandler(logger *zap.Logger, metrics *metricssvc.Service) Route {
	log := logger.With(zap.String("handler", "GetBucketMetrics"))
	return NewRoute(http.MethodGet, "/tenants/:tenantId/buckets/:bucketName/metrics", func(c echo.Context) error {
		from, to, window, err := metricsQuery(c)
		if err != nil {
			return metricsHTTPError(log, err)
		}
		samples, err := metrics.Bucket(c.Request().Context(), c.Param("tenantId"), c.Param("bucketName"), from, to, window)
		if err != nil {
			return metricsHTTPError(log, err)
		}
		return c.JSON(http.StatusOK, metricsResponse(samples))
	})
}

// metricsQuery reads the range and window every metrics request carries. All
// three are required, and a malformed one is a bad request rather than a
// semantic failure, so it never reaches the service.
func metricsQuery(c echo.Context) (time.Time, time.Time, time.Duration, error) {
	return metricssvc.ParseRange(c.QueryParam("from"), c.QueryParam("to"), c.QueryParam("window"))
}

// metricsResponse maps a usage series onto the wire.
//
// Egress is always an empty series. It is accounted for by the egress tracking
// service, which this API does not read, and reporting zero would claim a
// reading rather than admitting there is none.
func metricsResponse(samples []metricssvc.Sample) Metrics {
	storage := make([]StorageSample, 0, len(samples))
	ingress := make([]IngressSample, 0, len(samples))
	for _, s := range samples {
		storage = append(storage, StorageSample{
			Timestamp:   s.End,
			BytesUsed:   s.BytesStored,
			ObjectCount: s.ObjectCount,
		})
		ingress = append(ingress, IngressSample{
			Timestamp:     s.End,
			BytesIngested: s.BytesIngested,
		})
	}
	return Metrics{
		Storage: StorageMetrics{Samples: storage},
		Egress:  EgressMetrics{Samples: make([]EgressSample, 0)},
		Ingress: IngressMetrics{Samples: ingress},
	}
}
