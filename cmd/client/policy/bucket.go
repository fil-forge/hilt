package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/fil-forge/hilt/cmd/client/lib"
	"github.com/fil-forge/hilt/pkg/api"
	"github.com/spf13/cobra"
)

var ifMatch string

// readDocument reads a policy document from path, or from standard input when
// path is "-".
func readDocument(cmd *cobra.Command, path string) (api.BucketPolicy, error) {
	var (
		data []byte
		err  error
	)
	if path == "-" {
		data, err = io.ReadAll(cmd.InOrStdin())
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return api.BucketPolicy{}, fmt.Errorf("reading policy document: %w", err)
	}
	var doc api.BucketPolicy
	if err := json.Unmarshal(data, &doc); err != nil {
		return api.BucketPolicy{}, fmt.Errorf("decoding policy document: %w", err)
	}
	return doc, nil
}

var getCmd = &cobra.Command{
	Use:   "get <tenant-id> <bucket-name>",
	Short: "Show a bucket's policy and its ETag",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		doc, etag, err := c.GetBucketPolicy(cmd.Context(), args[0], args[1])
		if err != nil {
			return err
		}
		return lib.PrintJSON(cmd, struct {
			ETag   string           `json:"etag"`
			Policy api.BucketPolicy `json:"policy"`
		}{etag, doc})
	},
}

var createCmd = &cobra.Command{
	Use:   "create <tenant-id> <bucket-name> <document.json>",
	Short: "Write a bucket's first policy",
	Long: "Write a bucket's first policy, conditioned on the bucket having none. " +
		"The document is read from the given file, or from standard input when the " +
		"path is \"-\". A bucket that already has a policy is rejected; use replace.",
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		doc, err := readDocument(cmd, args[2])
		if err != nil {
			return err
		}
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		etag, err := c.CreateBucketPolicy(cmd.Context(), args[0], args[1], doc)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote the policy of bucket %s, ETag %s\n", args[1], etag)
		return nil
	},
}

var replaceCmd = &cobra.Command{
	Use:   "replace <tenant-id> <bucket-name> <document.json>",
	Short: "Replace a bucket's policy",
	Long: "Replace a bucket's policy, conditioned on --if-match being its current " +
		"ETag, which `policy get` reports. The document is read from the given " +
		"file, or from standard input when the path is \"-\".",
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		if ifMatch == "" {
			return fmt.Errorf("--if-match is required: pass the ETag `policy get` reports")
		}
		doc, err := readDocument(cmd, args[2])
		if err != nil {
			return err
		}
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		etag, err := c.ReplaceBucketPolicy(cmd.Context(), args[0], args[1], doc, ifMatch)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Replaced the policy of bucket %s, ETag %s\n", args[1], etag)
		return nil
	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete <tenant-id> <bucket-name>",
	Short: "Delete a bucket's policy",
	Long: "Delete a bucket's policy, conditioned on --if-match being its current " +
		"ETag. Every principal the policy reached loses its access to the bucket.",
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		if ifMatch == "" {
			return fmt.Errorf("--if-match is required: pass the ETag `policy get` reports")
		}
		c, _, err := lib.InitManagementClient(cmd)
		if err != nil {
			return err
		}
		if err := c.DeleteBucketPolicy(cmd.Context(), args[0], args[1], ifMatch); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Deleted the policy of bucket %s\n", args[1])
		return nil
	},
}

func init() {
	replaceCmd.Flags().StringVar(&ifMatch, "if-match", "", "the ETag the bucket's current policy must carry")
	deleteCmd.Flags().StringVar(&ifMatch, "if-match", "", "the ETag the bucket's current policy must carry")
}
