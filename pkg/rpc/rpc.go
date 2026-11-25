// Package rpc implements the Hilt UCAN RPC API — the S3 commands Ingot invokes
// on Hilt (see the Forge S3 tenant-management RFC). Each command is exposed as a
// [github.com/fil-forge/ucantone/server.Route] via its New*Handler constructor,
// collected via fx and registered on the UCAN server: /s3/request/authorize
// (authorize.go), /s3/bucket/{create,delete,info,list} (create.go, delete.go,
// info.go, list.go), /s3/usage/report (usage.go), and the self-issued admin
// commands /admin/provider/{add,list} and /admin/provider/nodes/set (admin.go).
// Authorization of the invocation itself lives in middleware, applied by pkg/fx
// when it registers the three route groups: the S3 commands require an
// invocation subjected to the service and issued by someone else, so authority
// over them comes from a delegation the service issued; the admin commands
// require one issued by the service's own identity; and the usage report, a
// provider's own account of what it did, requires one a registered provider
// issued over itself. Authentication and authorization shared by the
// signature-bearing commands live in the auth service (service/auth).
package rpc
