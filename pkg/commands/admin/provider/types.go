package provider

import "github.com/fil-forge/ucantone/did"

// AddArguments are the arguments to the /admin/provider/add command: the regional
// provider's DID, the region it serves, and the storage nodes it operates.
type AddArguments struct {
	Provider did.DID `cborgen:"provider" dagjsongen:"provider"`
	Region   string  `cborgen:"region" dagjsongen:"region"`
	// Nodes are the DIDs of the storage nodes the provider operates. They become
	// the candidates of the provider's routing policy and MUST be non-empty.
	Nodes []did.DID `cborgen:"nodes" dagjsongen:"nodes"`
}
