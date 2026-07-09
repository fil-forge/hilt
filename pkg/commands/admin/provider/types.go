package provider

import "github.com/fil-forge/ucantone/did"

// AddArguments are the arguments to the /admin/provider/add command: the regional
// provider's DID and the region it serves.
type AddArguments struct {
	Provider did.DID `cborgen:"provider" dagjsongen:"provider"`
	Region   string  `cborgen:"region" dagjsongen:"region"`
}
