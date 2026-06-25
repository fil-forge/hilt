package vault_test

import (
	"runtime"
	"testing"

	"github.com/fil-forge/hilt/internal/testutil"
	"github.com/fil-forge/hilt/pkg/vault"
	vaulthashicorp "github.com/fil-forge/hilt/pkg/vault/hashicorp"
	vaultmemory "github.com/fil-forge/hilt/pkg/vault/memory"
	vaultclient "github.com/hashicorp/vault-client-go"
	"github.com/stretchr/testify/require"
)

type VaultKind string

const (
	Memory    VaultKind = "memory"
	Hashicorp VaultKind = "hashicorp"
)

var vaultKinds = []VaultKind{Memory, Hashicorp}

func makeVault(t *testing.T, k VaultKind) vault.Vault {
	switch k {
	case Memory:
		return vaultmemory.New()
	case Hashicorp:
		return createHashicorpVault(t)
	}
	panic("unknown vault kind")
}

func createHashicorpVault(t *testing.T) vault.Vault {
	if testutil.IsRunningInCI(t) && runtime.GOOS == "linux" {
		if !testutil.IsDockerAvailable(t) {
			t.Fatalf("docker is expected in CI linux testing environments, but wasn't found")
		}
	}
	if !testutil.IsDockerAvailable(t) {
		t.SkipNow()
	}
	address, token := testutil.CreateVault(t)
	client, err := vaultclient.New(vaultclient.WithAddress(address))
	require.NoError(t, err)
	require.NoError(t, client.SetToken(token))
	return vaulthashicorp.New(client, "secret")
}

func TestVault(t *testing.T) {
	for _, k := range vaultKinds {
		t.Run(string(k), func(t *testing.T) {
			v := makeVault(t, k)

			t.Run("writes and reads a value", func(t *testing.T) {
				require.NoError(t, v.Write(t.Context(), "/tenant/alice", []byte("secret")))
				got, err := v.Read(t.Context(), "/tenant/alice")
				require.NoError(t, err)
				require.Equal(t, []byte("secret"), got)
			})

			t.Run("Read returns ErrNotFound for unknown key", func(t *testing.T) {
				_, err := v.Read(t.Context(), "/tenant/nobody")
				require.ErrorIs(t, err, vault.ErrNotFound)
			})

			t.Run("Write overwrites an existing value", func(t *testing.T) {
				key := "/tenant/bob"
				require.NoError(t, v.Write(t.Context(), key, []byte("first")))
				require.NoError(t, v.Write(t.Context(), key, []byte("second")))
				got, err := v.Read(t.Context(), key)
				require.NoError(t, err)
				require.Equal(t, []byte("second"), got)
			})

			t.Run("Delete removes a value", func(t *testing.T) {
				key := "/tenant/carol"
				require.NoError(t, v.Write(t.Context(), key, []byte("secret")))
				require.NoError(t, v.Delete(t.Context(), key))
				_, err := v.Read(t.Context(), key)
				require.ErrorIs(t, err, vault.ErrNotFound)
			})

			t.Run("Delete is idempotent for absent key", func(t *testing.T) {
				require.NoError(t, v.Delete(t.Context(), "/tenant/ghost"))
			})

			t.Run("stored bytes are isolated from caller mutation", func(t *testing.T) {
				key := "/tenant/dave"
				in := []byte("secret")
				require.NoError(t, v.Write(t.Context(), key, in))
				in[0] = 'X' // mutate caller's slice after Write

				got, err := v.Read(t.Context(), key)
				require.NoError(t, err)
				require.Equal(t, []byte("secret"), got)

				got[0] = 'Y' // mutate returned slice
				again, err := v.Read(t.Context(), key)
				require.NoError(t, err)
				require.Equal(t, []byte("secret"), again)
			})
		})
	}
}
