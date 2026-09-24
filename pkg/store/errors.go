package store

import "github.com/fil-forge/ucantone/errors"

const (
	// RecordExistsErrorName is the name given to an error where the record
	// already exists in the store.
	RecordExistsErrorName = "RecordExists"
	// RecordNotFoundErrorName is the name given to an error where the record
	// is not found in the store.
	RecordNotFoundErrorName = "RecordNotFound"
	// InvalidArgumentErrorName is the name given to an error where an argument
	// passed to a store operation is invalid.
	InvalidArgumentErrorName = "InvalidArgument"
	// PreconditionFailedErrorName is the name given to an error where a
	// compare-and-set write finds the record in a state other than the one the
	// caller conditioned on.
	PreconditionFailedErrorName = "PreconditionFailed"
	// LockTimeoutErrorName is the name given to an error where a statement gave
	// up waiting for a conflicting row or advisory lock.
	LockTimeoutErrorName = "LockTimeout"
)

var (
	// ErrRecordExists is returned when a record already exists in the store.
	ErrRecordExists = errors.New(RecordExistsErrorName, "record already exists")
	// ErrRecordNotFound is returned when a record is not found in the store.
	ErrRecordNotFound = errors.New(RecordNotFoundErrorName, "record not found")
	// ErrInvalidArgument is returned when an argument passed to a store
	// operation is invalid.
	ErrInvalidArgument = errors.New(InvalidArgumentErrorName, "invalid argument")
	// ErrPreconditionFailed is returned when a conditional write does not match
	// the stored record: an If-Match tag differs from the current one, or a
	// create finds a record already present. Nothing is written.
	ErrPreconditionFailed = errors.New(PreconditionFailedErrorName, "precondition failed")
	// ErrLockTimeout is returned when a statement waited [LockTimeout] for a
	// lock another transaction holds and gave up. Nothing is written. The call
	// is retryable: the conflicting write either commits or rolls back, and the
	// retry proceeds from whichever state it leaves.
	ErrLockTimeout = errors.New(LockTimeoutErrorName, "timed out waiting for a lock")
)
