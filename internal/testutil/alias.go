package testutil

import (
	"testing"

	"github.com/fil-forge/libforge/testutil"
	"github.com/ipfs/go-cid"
)

var (
	Alice        = testutil.Alice
	Bob          = testutil.Bob
	Carol        = testutil.Carol
	Mallory      = testutil.Mallory
	RandomBytes  = testutil.RandomBytes
	RandomDID    = testutil.RandomDID
	RandomSigner = testutil.RandomSigner
	RandomIssuer = testutil.RandomIssuer
)

func RandomCID(t *testing.T) cid.Cid {
	return testutil.RandomCID(t)
}

func Must[T any](val T, err error) func(*testing.T) T {
	return testutil.Must(val, err)
}
