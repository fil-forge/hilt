//go:build !codegen

package provider_test

import (
	"bytes"
	"testing"

	"github.com/fil-forge/hilt/pkg/commands/admin/provider"
	"github.com/fil-forge/libforge/testutil"
	"github.com/stretchr/testify/require"
)

// The list result carries an optional policy per provider, so both the present
// and the absent form have to survive the generated codecs.
func TestListOKRoundTrip(t *testing.T) {
	policy := testutil.RandomDID(t)
	in := &provider.ListOK{Providers: []provider.Provider{
		{Provider: testutil.RandomDID(t), Region: "ap-south-1"},
		{Provider: testutil.RandomDID(t), Region: "us-east-1", Policy: &policy},
	}}

	var cb bytes.Buffer
	require.NoError(t, in.MarshalCBOR(&cb))
	var fromCBOR provider.ListOK
	require.NoError(t, fromCBOR.UnmarshalCBOR(bytes.NewReader(cb.Bytes())))
	require.Equal(t, *in, fromCBOR)

	var jb bytes.Buffer
	require.NoError(t, in.MarshalDagJSON(&jb))
	var fromJSON provider.ListOK
	require.NoError(t, fromJSON.UnmarshalDagJSON(bytes.NewReader(jb.Bytes())))
	require.Equal(t, *in, fromJSON)
}

func TestListOKEmptyRoundTrip(t *testing.T) {
	in := &provider.ListOK{Providers: []provider.Provider{}}
	var cb bytes.Buffer
	require.NoError(t, in.MarshalCBOR(&cb))
	var out provider.ListOK
	require.NoError(t, out.UnmarshalCBOR(bytes.NewReader(cb.Bytes())))
	require.Empty(t, out.Providers)
}
