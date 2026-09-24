// Command gen-keypair generates an Ed25519 key pair for local test use (kind
// smoke tests) and prints both hex-encoded keys. Not used in production: real
// deployments source the scheduler's key material the way article 1 already
// does (Kubernetes Secret, operator-managed), this tool exists only so this
// repo's kind manifests/smoke tests have a real, freshly generated key rather
// than a hard-coded one committed to the repo.
package main

import (
	"fmt"
	"os"

	"github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
)

func main() {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate key pair:", err)
		os.Exit(1)
	}
	fmt.Printf("PUBLIC_KEY_HEX=%s\n", crypto.PubKeyToHex(pub))
	fmt.Printf("PRIVATE_KEY_HEX=%s\n", crypto.PrivKeyToHex(priv))
}
