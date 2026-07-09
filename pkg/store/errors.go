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
)

var (
	// ErrRecordExists is returned when a record already exists in the store.
	ErrRecordExists = errors.New(RecordExistsErrorName, "record already exists")
	// ErrRecordNotFound is returned when a record is not found in the store.
	ErrRecordNotFound = errors.New(RecordNotFoundErrorName, "record not found")
	// ErrInvalidArgument is returned when an argument passed to a store
	// operation is invalid.
	ErrInvalidArgument = errors.New(InvalidArgumentErrorName, "invalid argument")
)
