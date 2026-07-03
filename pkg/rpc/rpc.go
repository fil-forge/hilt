// Package rpc implements the Hilt UCAN RPC API — the S3 commands Ingot invokes
// on Hilt (see the Forge S3 tenant-management RFC). Each command is exposed as a
// [github.com/fil-forge/ucantone/server.Route] via its New*Handler constructor,
// collected via fx and registered on the UCAN server: /s3/request/authorize
// (authorize.go), /s3/bucket/{create,delete,info,list} (create.go, delete.go,
// info.go, list.go). Authentication and authorization shared by the
// signature-bearing commands live in the auth service (service/auth).
package rpc
