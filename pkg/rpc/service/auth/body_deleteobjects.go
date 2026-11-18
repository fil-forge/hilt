package auth

import (
	"encoding/xml"
	"fmt"
)

// maxDeleteObjectsEntries is the most keys a DeleteObjects may name, as S3
// bounds it; a body naming more is malformed and refused, as the gateway
// refuses it.
const maxDeleteObjectsEntries = 1000

// deleteObjectsBody is the shape of a DeleteObjects body hilt reads: the
// entries, each of which may name the version it deletes.
type deleteObjectsBody struct {
	Objects []struct {
		Key       string `xml:"Key"`
		VersionID string `xml:"VersionId"`
	} `xml:"Object"`
}

// readDeleteObjectsBody is the bodyReaders entry for DeleteObjects: an entry
// naming a version needs s3:DeleteObjectVersion beside s3:DeleteObject, as
// S3 requires for each such entry (hilt requires it for the whole request).
// An unparseable body, or one naming more keys than S3 allows, is refused.
func readDeleteObjectsBody(body []byte) ([]string, error) {
	var del deleteObjectsBody
	if err := xml.Unmarshal(body, &del); err != nil {
		return nil, fmt.Errorf("%w: unparseable DeleteObjects body: %v", ErrInvalidBody, err)
	}
	if len(del.Objects) > maxDeleteObjectsEntries {
		return nil, fmt.Errorf("%w: DeleteObjects body names %d keys, at most %d allowed", ErrInvalidBody, len(del.Objects), maxDeleteObjectsEntries)
	}
	for _, o := range del.Objects {
		if o.VersionID != "" {
			return []string{"s3:DeleteObjectVersion"}, nil
		}
	}
	return nil, nil
}
