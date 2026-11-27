// Package tasks names the durable task queues the service runs on the
// libforge task runner, and the actions on them.
//
// A queue runs at most one task per subject at a time. Both queues take the
// tenant's DID string as their subject, so the tasks of one tenant run one
// after another and those of different tenants run side by side.
package tasks

import "github.com/fil-forge/libforge/taskrunner"

// Schema is the Postgres schema the queues' tables live in: the one the goose
// migrations create the service's own tables in, which they name without a
// schema. The runner creates the schema if it is missing, which needs the
// CREATE privilege on the database even when the schema exists.
const Schema = "public"

const (
	// QueueTenant holds the changes to a tenant's authority: what its keys
	// may do. Authorization waits for a tenant's unfinished tasks here
	// before it answers for that tenant.
	QueueTenant = "queue-tenant"
	// QueueRevocation holds the publishing of the revocations a tenant owes.
	QueueRevocation = "queue-revocation"
)

// ActionSetStatus is queue-tenant.set-status: move the subject tenant to the
// status in the task's arguments, withdrawing or issuing its keys' grants as
// the change requires.
const ActionSetStatus = "set-status"

// ActionCreateKey is queue-tenant.create-key: create the access key in the
// task's arguments for the subject tenant, with the grants it holds.
const ActionCreateKey = "create-key"

// ActionDeleteKey is queue-tenant.delete-key: delete the subject tenant's
// access key named in the task's arguments, withdrawing the grants it holds.
const ActionDeleteKey = "delete-key"

// ActionPutPolicy is queue-tenant.put-policy: store the policy in the task's
// arguments for a bucket of the subject tenant, and give each access key of
// the principals it affects the grants it now holds over the bucket.
const ActionPutPolicy = "put-policy"

// ActionDeletePolicy is queue-tenant.delete-policy: remove the policy of the
// subject tenant's bucket named in the task's arguments, withdrawing the
// grants it gave over the bucket.
const ActionDeletePolicy = "delete-policy"

// ActionRemovePrincipal is queue-tenant.remove-principal: remove the subject
// tenant's principal named in the task's arguments, with its keys and its
// place in the tenant's bucket policies, withdrawing the grants they held.
const ActionRemovePrincipal = "remove-principal"

// ActionDeleteBucket is queue-tenant.delete-bucket: delete the subject
// tenant's bucket named in the task's arguments, once it is empty, with its
// policy, withdrawing the grants over it.
const ActionDeleteBucket = "delete-bucket"

// ActionDeleteTenant is queue-tenant.delete-tenant: delete the subject
// tenant, which must be disabled, after publishing the revocations it owes
// and those of its keys' grants and deactivating its DID.
const ActionDeleteTenant = "delete-tenant"

// ActionPublish is queue-revocation.publish: publish every revocation the
// subject tenant owes.
const ActionPublish = "publish"

// Queues lists the queues in order, with the number of async tasks of each
// this process runs at once. A task runs sync children only on the queues
// after its own, so a change on queue-tenant may run one on queue-revocation
// and never the reverse.
func Queues(tenantWorkers, revocationWorkers int) []taskrunner.QueueOptions {
	return []taskrunner.QueueOptions{
		{Name: QueueTenant, Workers: tenantWorkers},
		{Name: QueueRevocation, Workers: revocationWorkers},
	}
}
