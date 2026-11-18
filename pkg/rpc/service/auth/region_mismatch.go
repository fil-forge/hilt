package auth

import (
	"bytes"
	"fmt"
	"io"

	"github.com/fil-forge/hilt/pkg/rpc/service/auth/datamodel"
	ucanerrors "github.com/fil-forge/ucantone/errors"
	edm "github.com/fil-forge/ucantone/errors/datamodel"
)

// BucketRegionMismatchError is returned when a bucket the request addresses is
// served by a provider other than the one serving the request's region. The
// bucket exists and is the tenant's, but its data lives in another region, so
// the request must be re-sent to that region's endpoint.
//
// It carries both regions so the gateway can answer as S3 does: an
// AuthorizationHeaderMalformed error naming the expected region, which the AWS
// SDKs follow to the right endpoint without the caller noticing. It is a
// ucantone Named error and encodes itself on the wire as
// [datamodel.BucketRegionMismatch]: the standard error model plus the regions,
// so a reader that knows only the standard model still sees the name.
type BucketRegionMismatchError struct {
	// Expected is the region whose provider serves the bucket.
	Expected string
	// Actual is the region the request was signed for.
	Actual string
}

var _ ucanerrors.Named = (*BucketRegionMismatchError)(nil)

func (e *BucketRegionMismatchError) Name() string { return BucketRegionMismatchErrorName }

func (e *BucketRegionMismatchError) Error() string {
	return fmt.Sprintf("bucket is served by region %q; request was signed for %q", e.Expected, e.Actual)
}

// MarshalCBOR encodes the failure as [datamodel.BucketRegionMismatch]. A
// receipt's SetFailure marshals an error that implements this itself, which is
// how the regions reach the wire.
func (e *BucketRegionMismatchError) MarshalCBOR(w io.Writer) error {
	m := datamodel.BucketRegionMismatch{
		Name:     e.Name(),
		Message:  e.Error(),
		Expected: e.Expected,
		Actual:   e.Actual,
	}
	return m.MarshalCBOR(w)
}

// UnmarshalCBOR decodes a [datamodel.BucketRegionMismatch]. It rejects a model
// carrying another failure's name.
func (e *BucketRegionMismatchError) UnmarshalCBOR(r io.Reader) error {
	var m datamodel.BucketRegionMismatch
	if err := m.UnmarshalCBOR(r); err != nil {
		return err
	}
	if m.Name != BucketRegionMismatchErrorName {
		return fmt.Errorf("expected a %s failure, got %q", BucketRegionMismatchErrorName, m.Name)
	}
	e.Expected, e.Actual = m.Expected, m.Actual
	return nil
}

// DecodeFailure decodes the error value of a failed receipt into the failure
// Hilt issued: a *BucketRegionMismatchError for that failure, and the standard
// error model (name and message) for every other. Clients use it in place of
// the binding's generic unpack so structured failures keep their fields.
func DecodeFailure(b []byte) (ucanerrors.Named, error) {
	var model edm.ErrorModel
	if err := model.UnmarshalCBOR(bytes.NewReader(b)); err != nil {
		return nil, fmt.Errorf("decoding failure: %w", err)
	}
	if model.Name() != BucketRegionMismatchErrorName {
		return model, nil
	}
	var mismatch BucketRegionMismatchError
	if err := mismatch.UnmarshalCBOR(bytes.NewReader(b)); err != nil {
		return nil, fmt.Errorf("decoding %s failure: %w", model.Name(), err)
	}
	return &mismatch, nil
}
