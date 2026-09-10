package accesskey

import (
	"fmt"
	"time"

	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/spf13/cobra"
)

var (
	createPermissions []string
	createBuckets     []string
	createPrincipal   string
	createExpiresAt   string
)

var createCmd = &cobra.Command{
	Use:   "create <tenant-id> <name>",
	Short: "Create an access key for a tenant",
	Long: "Create an access key for a tenant. Without --principal it is a service " +
		"key carrying the permissions and buckets given here; with --principal it is " +
		"bound to that principal and takes neither, its access coming from the " +
		"tenant's bucket policies. The response includes the secret access key — " +
		"this is the only time it is exposed, so capture it now.",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if createPrincipal == "" && len(createPermissions) == 0 {
			return fmt.Errorf("--permissions is required for a service key (or pass --principal)")
		}
		req := api.CreateAccessKeyRequest{
			Name:        args[1],
			Permissions: createPermissions,
			Buckets:     createBuckets,
			PrincipalID: createPrincipal,
		}
		if createExpiresAt != "" {
			expires, err := time.Parse(time.RFC3339, createExpiresAt)
			if err != nil {
				return fmt.Errorf("parsing --expires-at (want RFC3339, e.g. 2027-01-02T15:04:05Z): %w", err)
			}
			req.ExpiresAt = &expires
		}
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		rec, err := c.CreateAccessKey(cmd.Context(), args[0], req)
		if err != nil {
			return err
		}
		return lib.PrintJSON(cmd, rec)
	},
}

func init() {
	createCmd.Flags().StringSliceVar(&createPermissions, "permissions", nil, "S3 permissions to grant (e.g. s3:GetObject,s3:PutObject)")
	createCmd.Flags().StringSliceVar(&createBuckets, "buckets", nil, "bucket DIDs the key is restricted to (default: all the tenant's buckets)")
	createCmd.Flags().StringVar(&createPrincipal, "principal", "", "bind the key to this principal (userId); the key takes no permissions or buckets")
	createCmd.Flags().StringVar(&createExpiresAt, "expires-at", "", "expiry as an RFC3339 timestamp (default: never expires)")
}
