package build

import "runtime/debug"

// revision is the VCS revision embedded by the compiler during build,
// truncated to 7 characters and suffixed with "-dirty" if the working tree was
// modified. "unknown" when no build info is available (e.g. `go run`).
// Initialized as a var (not in init) so it is set before version.go's init runs.
var revision = vcsRevision()

func vcsRevision() string {
	rev := "unknown"
	var dirty bool

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return rev
	}

	for _, bs := range bi.Settings {
		switch bs.Key {
		case "vcs.revision":
			rev = bs.Value
			if len(bs.Value) > 7 {
				rev = bs.Value[:7]
			}
		case "vcs.modified":
			if bs.Value == "true" {
				dirty = true
			}
		}
	}

	if dirty {
		rev += "-dirty"
	}

	return rev
}
