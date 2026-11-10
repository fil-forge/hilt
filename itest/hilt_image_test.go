//go:build itest

package itest

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	hiltImageOnce sync.Once
	hiltImage     string
	hiltImageErr  error
)

// hiltResolverImage adds the exact fixture caller to Hilt's environment while
// retaining the pinned Smelt image/binary override APIs. That Smelt revision
// cannot mount a Hilt config file and does not forward arbitrary host env vars.
// The tiny context contains only a Dockerfile, never repository files or keys.
func hiltResolverImage(t *testing.T) string {
	t.Helper()
	hiltImageOnce.Do(func() {
		base := os.Getenv("HILT_ITEST_HILT_IMAGE")
		if base == "" {
			base = "ghcr.io/fil-forge/hilt:main" // pinned Smelt's default
		}
		if strings.ContainsAny(base, " \t\r\n") {
			hiltImageErr = fmt.Errorf("HILT_ITEST_HILT_IMAGE must be one image reference")
			return
		}
		ctx := t.TempDir()
		dockerfile := "FROM " + base + "\nENV HILT_SERVER_ALLOWED_WEB_DIDS=did:web:ingot\n"
		if err := os.WriteFile(filepath.Join(ctx, "Dockerfile"), []byte(dockerfile), 0600); err != nil {
			hiltImageErr = err
			return
		}
		hiltImage = fmt.Sprintf("hilt-itest-allowlist:%d-%s", os.Getpid(), strings.ToLower(rand.Text()))
		cmd := exec.CommandContext(t.Context(), "docker", "build", "--quiet", "--tag", hiltImage, ctx)
		if out, err := cmd.CombinedOutput(); err != nil {
			hiltImageErr = fmt.Errorf("building Hilt allowlist fixture image: %v\n%s", err, out)
		}
	})
	if hiltImageErr != nil {
		t.Fatal(hiltImageErr)
	}
	return hiltImage
}

// Cleanup runs after all test stacks have stopped and removes only the unique
// image this process built. It never sweeps other test images or containers.
func cleanupHiltResolverImage() {
	if hiltImage == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "image", "rm", hiltImage).CombinedOutput(); err != nil {
		log.Printf("itest: removing own Hilt fixture image: %v\n%s", err, out)
	}
}
