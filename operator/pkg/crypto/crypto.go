// Package crypto provides the Ed25519 signing/verification and hashing
// primitives used across article 2's Operator and eBPF agent. The scheme
// (hex-encoded Ed25519 signatures and keys, SHA-256 hex digests, and a
// canonical-JSON form for hashing structured values) matches the one already
// in production use by article 1's scheduler
// (github.com/imperium/ai-sovereign-finops-operator/pkg/crypto), documented
// in EXPERIMENTS_LOG.md Phase 1, so a single verifier can check artifacts from
// either article.
package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// GenerateEd25519KeyPair generates a new Ed25519 key pair.
func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 key pair: %w", err)
	}
	return pub, priv, nil
}

// Ed25519Sign signs data and returns the signature as a hex string.
func Ed25519Sign(priv ed25519.PrivateKey, data []byte) string {
	sig := ed25519.Sign(priv, data)
	return hex.EncodeToString(sig)
}

// Ed25519Verify verifies a hex-encoded Ed25519 signature against data.
func Ed25519Verify(pub ed25519.PublicKey, data []byte, sigHex string) (bool, error) {
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("decode signature hex: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return false, fmt.Errorf("invalid ed25519 signature length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
	return ed25519.Verify(pub, data, sig), nil
}

// PrivKeyToHex encodes an Ed25519 private key as a hex string (32-byte seed only).
func PrivKeyToHex(priv ed25519.PrivateKey) string {
	return hex.EncodeToString(priv.Seed())
}

// PrivKeyFromHex reconstructs an Ed25519 private key from its hex-encoded seed.
func PrivKeyFromHex(h string) (ed25519.PrivateKey, error) {
	seed, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("decode private key hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid ed25519 seed length: got %d, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PubKeyToHex encodes an Ed25519 public key as a hex string.
func PubKeyToHex(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub)
}

// PubKeyFromHex reconstructs an Ed25519 public key from its hex-encoded form.
func PubKeyFromHex(h string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("decode public key hex: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key length: got %d, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// SHA256Hex returns the lowercase SHA-256 digest of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// CanonicalJSON marshals v into a deterministic JSON representation with
// recursively sorted object keys, so a hash computed over it is stable
// regardless of map iteration or struct field order at the call site.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical json input: %w", err)
	}

	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("unmarshal canonical json input: %w", err)
	}

	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, decoded); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalSHA256Hex returns the SHA-256 hex digest of CanonicalJSON(v).
func CanonicalSHA256Hex(v any) (string, error) {
	raw, err := CanonicalJSON(v)
	if err != nil {
		return "", err
	}
	return SHA256Hex(raw), nil
}

func writeCanonicalJSON(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64, string:
		raw, err := json.Marshal(t)
		if err != nil {
			return fmt.Errorf("marshal canonical scalar: %w", err)
		}
		buf.Write(raw)
	case []any:
		buf.WriteByte('[')
		for i, elem := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonicalJSON(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyJSON, err := json.Marshal(k)
			if err != nil {
				return fmt.Errorf("marshal canonical key: %w", err)
			}
			buf.Write(keyJSON)
			buf.WriteByte(':')
			if err := writeCanonicalJSON(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		raw, err := json.Marshal(t)
		if err != nil {
			return fmt.Errorf("marshal canonical fallback: %w", err)
		}
		buf.Write(raw)
	}
	return nil
}
