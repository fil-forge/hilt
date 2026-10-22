package auth

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"strings"

	"github.com/fil-forge/hilt/pkg/sigv4"
	s3 "github.com/fil-forge/libforge/commands/s3"
)

// MaxBodySize bounds a body hilt reads, matching the request codec's limit
// on the field. It holds the largest valid DeleteObjects document: a
// thousand entries of a kilobyte key expanded up to sixfold by XML
// escaping, a version id as long, and the conditional fields, about 7.3 MB.
const MaxBodySize = 8 << 20

// deleteObjectsBody is the shape of a DeleteObjects body hilt reads: the
// entries, each of which may name the version it deletes.
type deleteObjectsBody struct {
	Objects []struct {
		Key       string `xml:"Key"`
		VersionID string `xml:"VersionId"`
	} `xml:"Object"`
}

// readBody adds the permission the request's body puts on the operation: a
// DeleteObjects entry naming a version needs s3:DeleteObjectVersion beside
// s3:DeleteObject, as S3 requires for each such entry (hilt requires it for
// the whole request). A body on an operation that reads none, or missing
// from one that does, is refused by boundBody; an unparseable or oversized
// one is refused here.
func (c *classification) readBody(body []byte) error {
	if !c.op.ReadsBody() || len(body) == 0 {
		return nil
	}
	if len(body) > MaxBodySize {
		return fmt.Errorf("%w: a body of %d bytes exceeds %d", ErrUnboundBody, len(body), MaxBodySize)
	}
	var del deleteObjectsBody
	if err := xml.Unmarshal(body, &del); err != nil {
		return fmt.Errorf("%w: unparseable DeleteObjects body: %v", ErrUnboundBody, err)
	}
	for _, o := range del.Objects {
		if o.VersionID != "" {
			c.bodyPermissions = append(c.bodyPermissions, "s3:DeleteObjectVersion")
			break
		}
	}
	return nil
}

// bodyChecksumHeaders are the headers a client binds its body with when the
// payload itself is unsigned: S3 requires one of them on a DeleteObjects,
// and every x-amz-* header present must be signed. Each carries the
// base64 digest named.
var bodyChecksumHeaders = []struct {
	name string
	sum  func([]byte) []byte
}{
	{"x-amz-checksum-sha256", func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }},
	{"x-amz-checksum-sha1", func(b []byte) []byte { s := sha1.Sum(b); return s[:] }},
	{"x-amz-checksum-crc32", func(b []byte) []byte { return be32(crc32.ChecksumIEEE(b)) }},
	{"x-amz-checksum-crc32c", func(b []byte) []byte { return be32(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli))) }},
	{"x-amz-checksum-crc64nvme", func(b []byte) []byte { return be64(crc64.Checksum(b, crc64NVMeTable)) }},
	{"content-md5", func(b []byte) []byte { s := md5.Sum(b); return s[:] }},
}

// crc64NVMeTable is the reflected NVMe polynomial, as the SDKs compute
// x-amz-checksum-crc64nvme.
var crc64NVMeTable = crc64.MakeTable(0x9A6C9329AC4BC9B5)

func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func be64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// boundBody confirms a body hilt decides from is the one the signer sent:
// present exactly when the operation reads one, and covered by the
// signature, as the signed payload hash or, under an unsigned payload, by a
// signed checksum header. As S3 does, it refuses a checksum header the
// signature does not cover before any binding is accepted, and verifies
// every one present. The gateway acts on the body it received, which is
// the one forwarded here; what the binding settles is that the signer, and
// not a holder of a presigned URL, chose it.
func boundBody(sr *sigv4.SignedRequest, req s3.Request, op Operation) error {
	switch {
	case !op.ReadsBody():
		if len(req.Body) > 0 {
			return fmt.Errorf("%w: %s carries a body hilt does not read", ErrUnboundBody, op)
		}
		return nil
	case len(req.Body) == 0:
		return fmt.Errorf("%w: %s needs its body", ErrUnboundBody, op)
	}
	for _, h := range bodyChecksumHeaders {
		if _, ok := HeaderValue(req.Headers, h.name); ok && !sr.HeaderSigned(h.name) {
			return fmt.Errorf("%w: %s", ErrUnsignedHeader, h.name)
		}
	}
	if want := sr.PayloadHash(); want != sigv4.UnsignedPayload {
		sum := sha256.Sum256(req.Body)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
			return fmt.Errorf("%w: body does not hash to the signed payload hash", ErrUnboundBody)
		}
		return nil
	}
	bound := false
	for _, h := range bodyChecksumHeaders {
		v, ok := HeaderValue(req.Headers, h.name)
		if !ok {
			continue
		}
		if strings.TrimSpace(v) != base64.StdEncoding.EncodeToString(h.sum(req.Body)) {
			return fmt.Errorf("%w: body does not match the signed %s", ErrUnboundBody, h.name)
		}
		bound = true
	}
	if !bound {
		return fmt.Errorf("%w: body is covered by neither the payload hash nor a signed checksum header", ErrUnboundBody)
	}
	return nil
}
