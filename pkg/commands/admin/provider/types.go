package provider

import "github.com/fil-forge/ucantone/did"

// AddArguments are the arguments to the /admin/provider/add command: the regional
// provider's DID, the region it serves, and the storage nodes it operates.
type AddArguments struct {
	Provider did.DID `cborgen:"provider" dagjsongen:"provider"`
	Region   string  `cborgen:"region" dagjsongen:"region"`
	// Nodes are the DIDs of the storage nodes the provider operates. They become
	// the candidates of the provider's routing policy if they are non-empty.
	Nodes []did.DID `cborgen:"nodes" dagjsongen:"nodes"`
}

// Provider is one registered regional provider, as the /admin/provider/list
// command reports it.
type Provider struct {
	Provider did.DID `cborgen:"provider" dagjsongen:"provider"`
	Region   string  `cborgen:"region" dagjsongen:"region"`
	// Policy is the DID of the routing policy whose candidates are the
	// provider's storage nodes. Absent when the provider has none, in which
	// case the region's buckets use the upload service's default routing.
	Policy *did.DID `cborgen:"policy,omitempty" dagjsongen:"policy,omitempty"`
}

// ListOK is the result of /admin/provider/list: every registered provider,
// ordered by provider DID.
type ListOK struct {
	Providers []Provider `cborgen:"providers" dagjsongen:"providers"`
}
