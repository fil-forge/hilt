package vault

import "github.com/fil-forge/ucantone/errors"

// KeyNotFoundErrorName is the name given to an error where the key is not found
// in the vault.
const KeyNotFoundErrorName = "KeyNotFound"

// ErrNotFound is returned when no value exists for a key.
var ErrNotFound = errors.New(KeyNotFoundErrorName, "key not found")
