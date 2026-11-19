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

package jose

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/go-jose/go-jose/v4/json"
)

// The following tests pin the pre-existing NIST-curve ECDH-ES behaviour so the
// X25519 addition cannot change its headers or error semantics.

func TestECDHESNISTDirectHeaderShape(t *testing.T) {
	enc, err := NewEncrypter(A128GCM, Recipient{Algorithm: ECDH_ES, Key: &ecTestKey256.PublicKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(obj.protected)
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]interface{}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}

	if header["alg"] != "ECDH-ES" {
		t.Errorf("alg: got %v", header["alg"])
	}
	if header["enc"] != "A128GCM" {
		t.Errorf("enc: got %v", header["enc"])
	}
	epk, ok := header["epk"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing epk: %s", raw)
	}
	if epk["kty"] != "EC" || epk["crv"] != "P-256" {
		t.Errorf("unexpected EC epk: %v", epk)
	}
	if _, ok := epk["x"]; !ok {
		t.Error("EC epk missing x")
	}
	if _, ok := epk["y"]; !ok {
		t.Error("EC epk missing y")
	}
	if _, ok := epk["d"]; ok {
		t.Error("EC epk leaked d")
	}
}

func TestECDHESNISTDecryptErrorsUnchanged(t *testing.T) {
	priv := ecTestKey256
	generator := randomKeyGenerator{size: 16}
	recipient := recipientInfo{encryptedKey: []byte("not used")}
	dec := ecDecrypterSigner{privateKey: priv}

	// Missing epk.
	headers := rawHeader{}
	if err := headers.set(headerAlgorithm, ECDH_ES); err != nil {
		t.Fatal(err)
	}
	if _, err := dec.decryptKey(headers, &recipient, generator); err == nil ||
		err.Error() != "go-jose/go-jose: missing epk header" {
		t.Errorf("missing epk: got %v", err)
	}

	// Invalid epk JSON.
	invalid := json.RawMessage("invalid")
	headers[headerEPK] = &invalid
	if _, err := dec.decryptKey(headers, &recipient, generator); err == nil ||
		err.Error() != "go-jose/go-jose: invalid epk header" {
		t.Errorf("invalid epk: got %v", err)
	}

	// An X25519 epk must be rejected by the NIST-curve decrypter.
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := headers.set(headerEPK, &JSONWebKey{Key: xKey.PublicKey()}); err != nil {
		t.Fatal(err)
	}
	if _, err := dec.decryptKey(headers, &recipient, generator); err == nil ||
		err.Error() != "go-jose/go-jose: invalid epk header" {
		t.Errorf("X25519 epk into EC decrypter: got %v", err)
	}

	// Missing recipient.
	if _, err := dec.decryptKey(headers, nil, generator); err == nil ||
		err.Error() != "go-jose/go-jose: missing recipient" {
		t.Errorf("missing recipient: got %v", err)
	}

	// Unsupported algorithm with an otherwise valid epk.
	if err := headers.set(headerEPK, &JSONWebKey{Key: &ecTestKey256.PublicKey}); err != nil {
		t.Fatal(err)
	}
	if err := headers.set(headerAlgorithm, "XYZ"); err != nil {
		t.Fatal(err)
	}
	if _, err := dec.decryptKey(headers, &recipient, generator); err != ErrUnsupportedAlgorithm {
		t.Errorf("unsupported alg: got %v, want ErrUnsupportedAlgorithm", err)
	}

	// Missing JWE Encrypted Key in key-wrap mode.
	if err := headers.set(headerAlgorithm, ECDH_ES_A128KW); err != nil {
		t.Fatal(err)
	}
	empty := recipientInfo{}
	if _, err := dec.decryptKey(headers, &empty, generator); err == nil ||
		err.Error() != "go-jose/go-jose: missing JWE Encrypted Key" {
		t.Errorf("missing encrypted key: got %v", err)
	}
}

func TestECDHESNISTMismatchedCurve(t *testing.T) {
	// A well-formed epk on a different NIST curve than the recipient private
	// key must be rejected with the pre-existing error message, not panic.
	epk := json.RawMessage(`{"kty":"EC","crv":"P-384","x":"` +
		base64.RawURLEncoding.EncodeToString(ecTestKey384.PublicKey.X.Bytes()) + `","y":"` +
		base64.RawURLEncoding.EncodeToString(ecTestKey384.PublicKey.Y.Bytes()) + `"}`)
	headers := rawHeader{headerEPK: &epk}
	if err := headers.set(headerAlgorithm, ECDH_ES); err != nil {
		t.Fatal(err)
	}

	dec := ecDecrypterSigner{privateKey: ecTestKey256}
	recipient := recipientInfo{encryptedKey: []byte("not used")}
	_, err := dec.decryptKey(headers, &recipient, randomKeyGenerator{size: 16})
	if err == nil || err.Error() != "go-jose/go-jose: invalid public key in epk header" {
		t.Errorf("mismatched curve: got %v", err)
	}
}

func TestECDHESNISTKEKSizeIndependentOfCurve(t *testing.T) {
	// The KEK size for a key management algorithm must not depend on which
	// curve is used, and must match the X25519 path.
	cek := make([]byte, 16)
	keys := map[string]*ecdsa.PublicKey{
		"P-256": &ecTestKey256.PublicKey,
		"P-384": &ecTestKey384.PublicKey,
		"P-521": &ecTestKey521.PublicKey,
	}

	for alg, want := range map[KeyAlgorithm]int{
		ECDH_ES_A128KW: 16,
		ECDH_ES_A192KW: 24,
		ECDH_ES_A256KW: 32,
	} {
		for name, pub := range keys {
			enc := ecEncrypterVerifier{publicKey: pub}
			info, err := enc.encryptKey(cek, alg)
			if err != nil {
				t.Fatalf("%s/%s: %v", alg, name, err)
			}
			if len(info.encryptedKey) == 0 {
				t.Errorf("%s/%s: empty encrypted key", alg, name)
			}

			gen := ecKeyGenerator{size: want, algID: string(alg), publicKey: pub}
			kek, _, err := gen.genKey()
			if err != nil {
				t.Fatal(err)
			}
			if len(kek) != want {
				t.Errorf("%s/%s: KEK size %d, want %d", alg, name, len(kek), want)
			}
		}
	}
}
