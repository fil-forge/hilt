// Package datamodel holds the wire models of the authorizer's structured
// failures: failures that carry more than the standard ucantone error model's
// name and message, and so need their own encoders.
package datamodel

// BucketRegionMismatch is the wire form of a BucketRegionMismatch failure. It
// extends the standard error model (name, message) with the two regions a
// gateway needs to answer as S3 does, so a reader that knows only the standard
// model still decodes the name and message.
type BucketRegionMismatch struct {
	Name    string `cborgen:"name" dagjsongen:"name"`
	Message string `cborgen:"message" dagjsongen:"message"`
	// Expected is the region whose provider serves the bucket.
	Expected string `cborgen:"expected" dagjsongen:"expected"`
	// Actual is the region the request was signed for.
	Actual string `cborgen:"actual" dagjsongen:"actual"`
}
