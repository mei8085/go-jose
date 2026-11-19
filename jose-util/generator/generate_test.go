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

package generator

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestNewEncryptionKeyX25519(t *testing.T) {
	for _, alg := range []jose.KeyAlgorithm{
		jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW,
	} {
		pub, priv, err := NewEncryptionKey(alg, 255)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		xPriv, ok := priv.(*ecdh.PrivateKey)
		if !ok {
			t.Fatalf("%s: expected *ecdh.PrivateKey, got %T", alg, priv)
		}
		if xPriv.Curve() != ecdh.X25519() {
			t.Errorf("%s: expected X25519 curve", alg)
		}
		xPub, ok := pub.(*ecdh.PublicKey)
		if !ok {
			t.Fatalf("%s: expected *ecdh.PublicKey, got %T", alg, pub)
		}
		if string(xPub.Bytes()) != string(xPriv.PublicKey().Bytes()) {
			t.Errorf("%s: public key does not match private key", alg)
		}

		// The generated key must be usable in a JWK roundtrip.
		jwk := jose.JSONWebKey{Key: priv}
		raw, err := jwk.MarshalJSON()
		if err != nil {
			t.Fatalf("%s: marshal: %v", alg, err)
		}
		var parsed jose.JSONWebKey
		if err := parsed.UnmarshalJSON(raw); err != nil {
			t.Fatalf("%s: unmarshal: %v", alg, err)
		}
	}
}

func TestNewEncryptionKeyNISTStillWorks(t *testing.T) {
	for _, bits := range []int{0, 256, 384, 521} {
		pub, _, err := NewEncryptionKey(jose.ECDH_ES, bits)
		if err != nil {
			t.Fatalf("bits=%d: %v", bits, err)
		}
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			t.Errorf("bits=%d: expected *ecdsa.PublicKey, got %T", bits, pub)
		}
	}
}

func TestNewEncryptionKeyRejectsBadSize(t *testing.T) {
	if _, _, err := NewEncryptionKey(jose.ECDH_ES, 123); err == nil {
		t.Error("expected an error for an unsupported key size")
	}
}
