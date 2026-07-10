// Package build provides the version and build metadata for the running
// binary, set with ldflags at build time and falling back to version.json and
// the VCS revision embedded by the compiler for development builds.
package build

import (
	"encoding/json"
	"fmt"
	"os"
)

var (
	// version is the built version. Set with ldflags via
	// -X github.com/fil-forge/hilt/pkg/build.version=v{{.Version}} (see Makefile).
	version string
	// Version is the current version of the application, including the VCS
	// revision (e.g. "v0.1.0-abc1234").
	Version string

	// Commit is the git commit hash.
	Commit = "unknown"

	// Date is the build date in UTC.
	Date = "unknown"

	// BuiltBy indicates what built this binary.
	BuiltBy = "unknown"
)

const (
	defaultVersion string = "v0.0.0"       // Default version if not set by ldflags
	versionFile    string = "version.json" // Version file path
)

func init() {
	if version == "" {
		// This is being run in development, try to grab the latest known version
		// from the version.json file.
		var err error
		version, err = readVersionFromFile()
		if err != nil {
			// Use the default version
			version = defaultVersion
		}
	}

	Version = fmt.Sprintf("%s-%s", version, revision)
}

// versionJSON is used to read the local version.json file.
type versionJSON struct {
	Version string `json:"version"`
}

// readVersionFromFile reads the version from the version.json file in the
// working directory (present when running from a source checkout).
func readVersionFromFile() (string, error) {
	file, err := os.Open(versionFile)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var vJSON versionJSON
	if err := json.NewDecoder(file).Decode(&vJSON); err != nil {
		return "", err
	}
	return vJSON.Version, nil
}
