package crypto

import "testing"

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	data := []byte(`{"pod_uid":"abc"}`)
	sig := Ed25519Sign(priv, data)

	ok, err := Ed25519Verify(pub, data, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("expected signature to verify")
	}
}

func TestVerifyRejectsTamperedData(t *testing.T) {
	pub, priv, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	sig := Ed25519Sign(priv, []byte("original"))

	ok, err := Ed25519Verify(pub, []byte("tampered"), sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected signature verification to fail for tampered data")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	pub1, _, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair 1: %v", err)
	}
	_, priv2, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair 2: %v", err)
	}
	data := []byte("payload")
	sig := Ed25519Sign(priv2, data)

	ok, err := Ed25519Verify(pub1, data, sig)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected signature verification to fail for wrong public key")
	}
}

func TestKeyHexRoundTrip(t *testing.T) {
	pub, priv, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	privHex := PrivKeyToHex(priv)
	gotPriv, err := PrivKeyFromHex(privHex)
	if err != nil {
		t.Fatalf("PrivKeyFromHex: %v", err)
	}
	if gotPriv.Equal(priv) == false {
		t.Fatal("private key round-trip mismatch")
	}

	pubHex := PubKeyToHex(pub)
	gotPub, err := PubKeyFromHex(pubHex)
	if err != nil {
		t.Fatalf("PubKeyFromHex: %v", err)
	}
	if !gotPub.Equal(pub) {
		t.Fatal("public key round-trip mismatch")
	}
}

func TestPrivKeyFromHexRejectsBadLength(t *testing.T) {
	if _, err := PrivKeyFromHex("deadbeef"); err == nil {
		t.Fatal("expected error for short seed")
	}
}

func TestSHA256HexKnownVector(t *testing.T) {
	// echo -n "" | sha256sum
	got := SHA256Hex([]byte(""))
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Fatalf("SHA256Hex(\"\") = %s, want %s", got, want)
	}
}

func TestCanonicalJSONSortsKeys(t *testing.T) {
	a := map[string]any{"b": 1, "a": 2}
	b := map[string]any{"a": 2, "b": 1}

	rawA, err := CanonicalJSON(a)
	if err != nil {
		t.Fatalf("CanonicalJSON(a): %v", err)
	}
	rawB, err := CanonicalJSON(b)
	if err != nil {
		t.Fatalf("CanonicalJSON(b): %v", err)
	}
	if string(rawA) != string(rawB) {
		t.Fatalf("expected identical canonical JSON regardless of map insertion order, got %q vs %q", rawA, rawB)
	}
	want := `{"a":2,"b":1}`
	if string(rawA) != want {
		t.Fatalf("CanonicalJSON = %q, want %q", rawA, want)
	}
}

func TestCanonicalSHA256HexDeterministic(t *testing.T) {
	h1, err := CanonicalSHA256Hex(map[string]any{"x": 1, "y": "z"})
	if err != nil {
		t.Fatalf("CanonicalSHA256Hex: %v", err)
	}
	h2, err := CanonicalSHA256Hex(map[string]any{"y": "z", "x": 1})
	if err != nil {
		t.Fatalf("CanonicalSHA256Hex: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("expected deterministic hash regardless of key order, got %s vs %s", h1, h2)
	}
}
