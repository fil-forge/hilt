package tenantqueue_test

import (
	"bytes"
	"testing"

	s3bkt "github.com/fil-forge/libforge/commands/s3/bucket"

	"github.com/fil-forge/hilt/pkg/store"
	"github.com/fil-forge/hilt/pkg/tasks"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue"
	"github.com/fil-forge/hilt/pkg/tasks/tenantqueue/datamodel"
	"github.com/fil-forge/libforge/taskrunner"
	"github.com/fil-forge/libforge/testutil"
	"github.com/stretchr/testify/require"
)

// policyOf returns a policy for the world's bucket that lets its principal
// do the actions.
func policyOf(actions ...string) s3bkt.PolicyDocument {
	return s3bkt.PolicyDocument{Version: s3bkt.Version2012, Statements: []s3bkt.Statement{{
		Effect: s3bkt.Allow, Principal: s3bkt.Only(principal), Actions: s3bkt.NewStringSet(actions...),
		Resources: s3bkt.NewStringSet(s3bkt.BucketARN(bucketName), s3bkt.ObjectsARN(bucketName)),
	}}}
}

func TestPolicySpecs(t *testing.T) {
	tenant, bucket := testutil.RandomDID(t), testutil.RandomDID(t)
	etag := `"0a1b2c"`

	t.Run("a write's arguments carry the bucket, its name, the document and the condition", func(t *testing.T) {
		document := policyOf("s3:GetObject", "s3:PutObject")
		for name, cond := range map[string]tenantqueue.PolicyCondition{
			"unconditional": {},
			"If-Match":      {Conditional: true, IfMatch: &etag},
			"If-None-Match": {Conditional: true},
		} {
			spec, err := tenantqueue.PutPolicySpec(tenant, bucket, bucketName, document, cond)
			require.NoError(t, err, name)
			require.Equal(t, tasks.QueueTenant, spec.Queue)
			require.Equal(t, tasks.ActionPutPolicy, spec.Action)
			require.Equal(t, tenant.String(), spec.Subject)

			var args datamodel.PutPolicyArgs
			require.NoError(t, args.UnmarshalCBOR(bytes.NewReader(spec.Args)), name)
			require.Equal(t, bucket, args.Bucket)
			require.Equal(t, bucketName, args.Name)
			require.Equal(t, s3bkt.ETag(document), s3bkt.ETag(args.Document))
			require.Equal(t, cond.Conditional, args.Conditional, name)
			require.Equal(t, cond.IfMatch, args.IfMatch, name)
		}
	})

	t.Run("a write's result decodes to the ETag and whether the policy was created", func(t *testing.T) {
		for _, want := range []datamodel.PutPolicyResult{{ETag: etag, Created: true}, {ETag: etag}} {
			var wire bytes.Buffer
			require.NoError(t, want.MarshalCBOR(&wire))
			got, created, err := tenantqueue.DecodePutPolicyResult(wire.Bytes())
			require.NoError(t, err)
			require.Equal(t, want.ETag, got)
			require.Equal(t, want.Created, created)
		}
		_, _, err := tenantqueue.DecodePutPolicyResult([]byte("junk"))
		require.Error(t, err)
	})

	t.Run("a removal's arguments carry the bucket, its name and the condition", func(t *testing.T) {
		for name, ifMatch := range map[string]*string{"unconditional": nil, "If-Match": &etag} {
			spec, err := tenantqueue.DeletePolicySpec(tenant, bucket, bucketName, ifMatch)
			require.NoError(t, err, name)
			require.Equal(t, tasks.QueueTenant, spec.Queue)
			require.Equal(t, tasks.ActionDeletePolicy, spec.Action)
			require.Equal(t, tenant.String(), spec.Subject)

			var args datamodel.DeletePolicyArgs
			require.NoError(t, args.UnmarshalCBOR(bytes.NewReader(spec.Args)), name)
			require.Equal(t, datamodel.DeletePolicyArgs{Bucket: bucket, Name: bucketName, IfMatch: ifMatch}, args, name)
		}
	})
}

// TestPolicyTasks covers what the policy handlers report and refuse. What
// they write, and how their commits hold against the writers outside the
// queue, is covered through the policy service
// (pkg/api/service/bucketpolicy).
func TestPolicyTasks(t *testing.T) {
	put := func(t *testing.T, w *world, document s3bkt.PolicyDocument, cond tenantqueue.PolicyCondition) taskrunner.Spec {
		t.Helper()
		spec, err := tenantqueue.PutPolicySpec(w.tenant.DID(), w.bucket, bucketName, document, cond)
		require.NoError(t, err)
		return spec
	}

	t.Run("a write reports the new ETag and that the policy was replaced", func(t *testing.T) {
		w := setup(t)
		document := policyOf("s3:GetObject", "s3:PutObject")
		res, err := w.runner.Run(t.Context(), put(t, w, document, tenantqueue.PolicyCondition{}))
		require.NoError(t, err)
		etag, created, err := tenantqueue.DecodePutPolicyResult(res)
		require.NoError(t, err)
		require.Equal(t, s3bkt.ETag(document), etag)
		require.False(t, created, "the world's bucket has a policy")

		rec, err := w.policies.Get(t.Context(), w.bucket)
		require.NoError(t, err)
		require.Equal(t, etag, rec.ETag)
	})

	t.Run("refusals are final and write nothing", func(t *testing.T) {
		w := setup(t)
		before, err := w.policies.Get(t.Context(), w.bucket)
		require.NoError(t, err)
		stale := `"stale"`
		missing := testutil.RandomDID(t)
		unknown := policyOf("s3:GetObject")
		unknown.Statements[0].Principal = s3bkt.Only("nobody")
		elsewhere := policyOf("s3:GetObject")
		elsewhere.Statements[0].Resources = s3bkt.NewStringSet(s3bkt.BucketARN("another"))
		missingPut, err := tenantqueue.PutPolicySpec(w.tenant.DID(), missing, bucketName, policyOf("s3:GetObject"), tenantqueue.PolicyCondition{})
		require.NoError(t, err)
		missingDelete, err := tenantqueue.DeletePolicySpec(w.tenant.DID(), missing, bucketName, nil)
		require.NoError(t, err)
		staleDelete, err := tenantqueue.DeletePolicySpec(w.tenant.DID(), w.bucket, bucketName, &stale)
		require.NoError(t, err)

		for name, tc := range map[string]struct {
			spec taskrunner.Spec
			want error
		}{
			"a write under a stale If-Match":             {put(t, w, policyOf("s3:PutObject"), tenantqueue.PolicyCondition{Conditional: true, IfMatch: &stale}), store.ErrPreconditionFailed},
			"a create over a policy":                     {put(t, w, policyOf("s3:PutObject"), tenantqueue.PolicyCondition{Conditional: true}), store.ErrPreconditionFailed},
			"a document naming a principal not there":    {put(t, w, unknown, tenantqueue.PolicyCondition{}), s3bkt.ErrInvalidPolicy},
			"a document for another bucket":              {put(t, w, elsewhere, tenantqueue.PolicyCondition{}), s3bkt.ErrInvalidPolicy},
			"a write to a bucket the tenant lacks":       {missingPut, tenantqueue.ErrUnknownBucket},
			"a removal from a bucket the tenant lacks":   {missingDelete, tenantqueue.ErrUnknownBucket},
			"a removal under a stale If-Match":           {staleDelete, store.ErrPreconditionFailed},
			"a write whose arguments are not a policy":   {taskrunner.Spec{Queue: tasks.QueueTenant, Subject: w.tenant.DID().String(), Action: tasks.ActionPutPolicy, Args: []byte("junk")}, nil},
			"a removal whose arguments are not a bucket": {taskrunner.Spec{Queue: tasks.QueueTenant, Subject: w.tenant.DID().String(), Action: tasks.ActionDeletePolicy, Args: []byte("junk")}, nil},
		} {
			t.Run(name, func(t *testing.T) {
				err := w.run(t, tc.spec)
				require.Error(t, err)
				if tc.want != nil {
					require.ErrorIs(t, err, tc.want)
				}
				require.True(t, taskrunner.IsPermanent(err), "the refusal is final")
				after, err := w.policies.Get(t.Context(), w.bucket)
				require.NoError(t, err)
				require.Equal(t, before.ETag, after.ETag)
				require.Empty(t, w.owedLinks(t))
			})
		}
	})

	t.Run("a removal of a policy the bucket does not have is final", func(t *testing.T) {
		w := setup(t)
		spec, err := tenantqueue.DeletePolicySpec(w.tenant.DID(), w.bucket, bucketName, nil)
		require.NoError(t, err)
		require.NoError(t, w.run(t, spec))
		err = w.run(t, spec)
		require.ErrorIs(t, err, tenantqueue.ErrPolicyNotFound)
		require.True(t, taskrunner.IsPermanent(err))
	})
}
