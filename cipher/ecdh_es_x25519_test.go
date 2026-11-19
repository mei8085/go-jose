/*-
 * Copyright 2026 The Go JOSE Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package josecipher

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// RFC 8037, Appendix A.6.
var rfc8037 = struct {
	// Receiver ("Bob") public key.
	recvPub []byte
	// Ephemeral private key chosen by the sender.
	ephPriv []byte
	// Ephemeral public key X25519(ephPriv, G).
	ephPub []byte
	// The raw DH Z value computed by both sides.
	z []byte
}{
	recvPub: mustHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
	ephPriv: mustHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
	ephPub:  mustHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
	z:       mustHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex test data: " + err.Error())
	}
	return b
}

func TestRFC8037X25519SharedSecret(t *testing.T) {
	recvPub, err := ecdh.X25519().NewPublicKey(rfc8037.recvPub)
	if err != nil {
		t.Fatal(err)
	}
	ephPriv, err := ecdh.X25519().NewPrivateKey(rfc8037.ephPriv)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(ephPriv.PublicKey().Bytes(), rfc8037.ephPub) {
		t.Errorf("ephemeral public key: got %x, want %x", ephPriv.PublicKey().Bytes(), rfc8037.ephPub)
	}

	z, err := ephPriv.ECDH(recvPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(z, rfc8037.z) {
		t.Errorf("shared secret: got %x, want %x", z, rfc8037.z)
	}
}

func TestDeriveECDHESX25519(t *testing.T) {
	recvPub, err := ecdh.X25519().NewPublicKey(rfc8037.recvPub)
	if err != nil {
		t.Fatal(err)
	}
	ephPriv, err := ecdh.X25519().NewPrivateKey(rfc8037.ephPriv)
	if err != nil {
		t.Fatal(err)
	}

	apuData := []byte("Alice")
	apvData := []byte("Bob")

	out, err := DeriveECDHESX25519("A128GCM", apuData, apvData, ephPriv, recvPub, 16)
	if err != nil {
		t.Fatal(err)
	}

	// Cross-check the same inputs through the generic ConcatKDF construction.
	algID := lengthPrefixed([]byte("A128GCM"))
	supPubInfo := []byte{0, 0, 0, 16 * 8}
	reader := NewConcatKDF(crypto.SHA256, rfc8037.z, algID, lengthPrefixed(apuData), lengthPrefixed(apvData), supPubInfo, []byte{})
	expected := make([]byte, 16)
	_, _ = reader.Read(expected)

	if !bytes.Equal(out, expected) {
		t.Errorf("derived key: got %x, want %x", out, expected)
	}
	if len(out) != 16 {
		t.Errorf("derived key length: got %d, want 16", len(out))
	}
}

func TestDeriveECDHESX25519Sizes(t *testing.T) {
	recvPub, err := ecdh.X25519().NewPublicKey(rfc8037.recvPub)
	if err != nil {
		t.Fatal(err)
	}
	ephPriv, err := ecdh.X25519().NewPrivateKey(rfc8037.ephPriv)
	if err != nil {
		t.Fatal(err)
	}

	for _, size := range []int{16, 24, 32, 64} {
		out, err := DeriveECDHESX25519("ECDH-ES+A128KW", nil, nil, ephPriv, recvPub, size)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if len(out) != size {
			t.Errorf("size %d: got %d bytes", size, len(out))
		}
	}
}

// TestDeriveECDHESX25519Vectors pins the ConcatKDF output for the RFC 8037
// A.6 keys across the algorithm identifiers used by the different ECDH-ES
// modes. The expected values were cross-checked against an independent
// implementation of the JWA ConcatKDF.
func TestDeriveECDHESX25519Vectors(t *testing.T) {
	recvPub, err := ecdh.X25519().NewPublicKey(rfc8037.recvPub)
	if err != nil {
		t.Fatal(err)
	}
	ephPriv, err := ecdh.X25519().NewPrivateKey(rfc8037.ephPriv)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		alg  string
		apu  []byte
		apv  []byte
		size int
		want string
	}{
		// Direct key agreement uses the content encryption algorithm as algID.
		{"A128GCM", []byte("Alice"), []byte("Bob"), 16, "a6e354fdfc89b00660736b6f10595112"},
		{"A128GCM", []byte("Alice"), []byte("Bob"), 24, "b75bb39a8620e8b089a13c934557fe878ea3f1b86491ffa8"},
		{"A128GCM", []byte("Alice"), []byte("Bob"), 32, "45ea9960ccd335bba6b7618c181aca8d37ad02105215a7cc48ebf42c64def37d"},
		{"A128GCM", nil, nil, 16, "ea3ff64f86e83c4e53d05e804aee7a5e"},
		// Key wrapping uses the key management algorithm as algID.
		{"ECDH-ES+A128KW", nil, nil, 16, "916caad566d5fbf2edd4729a92da1a05"},
		{"ECDH-ES+A192KW", nil, nil, 24, "2d675c035c456ac6c0ffa152796e6907cca12c28cd0e7c10"},
		{"ECDH-ES+A256KW", nil, nil, 32, "d1e6b2019fbfba04389ae1780381761c7e7219e2c21470d5ce47f661e7cbdb76"},
	}

	for _, tc := range cases {
		out, err := DeriveECDHESX25519(tc.alg, tc.apu, tc.apv, ephPriv, recvPub, tc.size)
		if err != nil {
			t.Fatalf("%s: %v", tc.alg, err)
		}
		if got := hex.EncodeToString(out); got != tc.want {
			t.Errorf("%s/%d: got %s, want %s", tc.alg, tc.size, got, tc.want)
		}
	}
}

func TestDeriveECDHESX25519RejectsMismatch(t *testing.T) {
	xPriv, err := ecdh.X25519().NewPrivateKey(rfc8037.ephPriv)
	if err != nil {
		t.Fatal(err)
	}

	// A P-256 key must not be accepted in place of an X25519 key.
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := DeriveECDHESX25519("A128GCM", nil, nil, xPriv, p256.PublicKey(), 16); err == nil {
		t.Error("expected error deriving with mismatched curves")
	}

	// Low-order public keys must be rejected by crypto/ecdh.
	lowOrder, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DeriveECDHESX25519("A128GCM", nil, nil, xPriv, lowOrder, 16); err == nil {
		t.Error("expected error deriving with low-order public key")
	}

	if _, err := DeriveECDHESX25519("A128GCM", nil, nil, nil, nil, 16); err == nil {
		t.Error("expected error deriving with nil keys")
	}
}
