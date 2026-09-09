package nodes

import "github.com/fil-forge/ucantone/did"

// SetArguments are the arguments to the /admin/provider/nodes/set command: the
// regional provider's DID and the complete set of storage nodes it operates.
type SetArguments struct {
	Provider did.DID `cborgen:"provider" dagjsongen:"provider"`
	// Nodes replaces the candidates of the provider's routing policy and MUST be
	// non-empty.
	Nodes []did.DID `cborgen:"nodes" dagjsongen:"nodes"`
}
