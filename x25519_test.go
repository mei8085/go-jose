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
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4/json"
)

// rfc8037BobPublicJWK is the receiver public key from RFC 8037, Appendix A.6.
const rfc8037BobPublicJWK = `{"kty":"OKP","crv":"X25519","kid":"Bob",` +
	`"x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}`

func newTestX25519Key(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate X25519 key: %v", err)
	}
	return key
}

func TestX25519JWKRoundtrip(t *testing.T) {
	priv := newTestX25519Key(t)

	for _, key := range []interface{}{priv, priv.PublicKey()} {
		jwk := JSONWebKey{Key: key, KeyID: "kid"}
		raw, err := jwk.MarshalJSON()
		if err != nil {
			t.Fatalf("marshal %T: %v", key, err)
		}

		var want map[string]interface{}
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
		if want["kty"] != "OKP" || want["crv"] != "X25519" {
			t.Errorf("unexpected kty/crv in %s", raw)
		}
		if _, ok := want["x"]; !ok {
			t.Errorf("missing x in %s", raw)
		}
		_, hasD := want["d"]
		if hasD != (jwk.Key == priv) {
			t.Errorf("private key material mismatch, hasD=%v in %s", hasD, raw)
		}

		var parsed JSONWebKey
		if err := parsed.UnmarshalJSON(raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		if parsed.KeyID != "kid" {
			t.Errorf("kid did not roundtrip: %q", parsed.KeyID)
		}

		var wantPub []byte
		switch k := parsed.Key.(type) {
		case *ecdh.PrivateKey:
			wantPub = k.PublicKey().Bytes()
		case *ecdh.PublicKey:
			wantPub = k.Bytes()
		default:
			t.Fatalf("unexpected key type %T", parsed.Key)
		}
		if !bytes.Equal(wantPub, priv.PublicKey().Bytes()) {
			t.Errorf("public key did not roundtrip")
		}
	}
}

func TestX25519JWKPrivateMatchesPublic(t *testing.T) {
	priv := newTestX25519Key(t)

	// A private JWK whose x does not match d must be rejected.
	other := newTestX25519Key(t)
	raw := []byte(`{"kty":"OKP","crv":"X25519","x":"` +
		base64.RawURLEncoding.EncodeToString(other.PublicKey().Bytes()) +
		`","d":"` + base64.RawURLEncoding.EncodeToString(priv.Bytes()) + `"}`)

	var jwk JSONWebKey
	err := jwk.UnmarshalJSON(raw)
	if err == nil || !strings.Contains(err.Error(), "x does not match d") {
		t.Fatalf("expected x/d mismatch error, got %v", err)
	}
}

func TestX25519JWKRejectsMalformed(t *testing.T) {
	valid := newTestX25519Key(t)
	validPub := base64.RawURLEncoding.EncodeToString(valid.PublicKey().Bytes())

	cases := map[string]string{
		"missing x":             `{"kty":"OKP","crv":"X25519"}`,
		"short x":               `{"kty":"OKP","crv":"X25519","x":"AAAA"}`,
		"low order zero":        `{"kty":"OKP","crv":"X25519","x":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}`,
		"low order one":         `{"kty":"OKP","crv":"X25519","x":"` + base64.RawURLEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...)) + `"}`,
		"missing d":             `{"kty":"OKP","crv":"X25519","x":"` + validPub + `","d":""}`,
		"short d":               `{"kty":"OKP","crv":"X25519","x":"` + validPub + `","d":"AAAA"}`,
		"low order private x":   `{"kty":"OKP","crv":"X25519","x":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `","d":"` + base64.RawURLEncoding.EncodeToString(valid.Bytes()) + `"}`,
		"unknown OKP curve alg": `{"kty":"OKP","crv":"X448","x":"` + validPub + `"}`,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			var jwk JSONWebKey
			if err := jwk.UnmarshalJSON([]byte(raw)); err == nil {
				t.Errorf("accepted malformed X25519 JWK: %s", raw)
			}
		})
	}
}

func TestX25519JWKParseRFC8037(t *testing.T) {
	var jwk JSONWebKey
	if err := jwk.UnmarshalJSON([]byte(rfc8037BobPublicJWK)); err != nil {
		t.Fatal(err)
	}
	pub, ok := jwk.Key.(*ecdh.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdh.PublicKey, got %T", jwk.Key)
	}
	want, _ := base64.RawURLEncoding.DecodeString("3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08")
	if !bytes.Equal(pub.Bytes(), want) {
		t.Errorf("parsed public key mismatch: got %x want %x", pub.Bytes(), want)
	}
	if jwk.KeyID != "Bob" {
		t.Errorf("kid: got %q want Bob", jwk.KeyID)
	}
}

func TestX25519JWKThumbprint(t *testing.T) {
	var jwk JSONWebKey
	if err := jwk.UnmarshalJSON([]byte(rfc8037BobPublicJWK)); err != nil {
		t.Fatal(err)
	}

	got, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	// RFC 7638: the canonical form is the required members in lexicographic
	// order: crv, kty, x.
	wantInput := `{"crv":"X25519","kty":"OKP","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}`
	want := sha256.Sum256([]byte(wantInput))
	if !bytes.Equal(got, want[:]) {
		t.Errorf("thumbprint mismatch: got %x want %x", got, want)
	}

	// The private key must produce the same thumbprint as its public half.
	priv := newTestX25519Key(t)
	privThumb, err := (&JSONWebKey{Key: priv}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pubThumb, err := (&JSONWebKey{Key: priv.PublicKey()}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privThumb, pubThumb) {
		t.Errorf("private and public thumbprints differ")
	}
}

func TestX25519JWKPublic(t *testing.T) {
	priv := newTestX25519Key(t)
	jwk := JSONWebKey{Key: priv, KeyID: "x"}

	if jwk.IsPublic() {
		t.Fatal("private key reported as public")
	}
	pub := jwk.Public()
	pubKey, ok := pub.Key.(*ecdh.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdh.PublicKey, got %T", pub.Key)
	}
	if !bytes.Equal(pubKey.Bytes(), priv.PublicKey().Bytes()) {
		t.Error("public key mismatch")
	}
	if !pub.IsPublic() {
		t.Error("Public() result not reported as public")
	}
	if !jwk.Valid() || !pub.Valid() {
		t.Error("X25519 JWK reported invalid")
	}
}

func TestX25519JWERoundtrip(t *testing.T) {
	priv := newTestX25519Key(t)

	keyAlgs := []KeyAlgorithm{ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW}
	encAlgs := []ContentEncryption{A128GCM, A192GCM, A256GCM, A128CBC_HS256, A192CBC_HS384, A256CBC_HS512}

	noCorruption := func(obj *JSONWebEncryption) bool { return false }

	for _, alg := range keyAlgs {
		for _, enc := range encAlgs {
			t.Run(string(alg)+"/"+string(enc), func(t *testing.T) {
				// Exercise raw keys, a JSONWebKey and a JWK set.
				keys := []struct {
					enc, dec interface{}
				}{
					{enc: priv.PublicKey(), dec: priv},
					{enc: &JSONWebKey{KeyID: "x", Key: priv.PublicKey()}, dec: &JSONWebKey{KeyID: "x", Key: priv}},
				}

				for _, key := range keys {
					for _, serializer := range []func(*JSONWebEncryption) (string, error){
						func(obj *JSONWebEncryption) (string, error) { return obj.CompactSerialize() },
						func(obj *JSONWebEncryption) (string, error) { return obj.FullSerialize(), nil },
					} {
						if err := RoundtripJWE(t, alg, enc, NONE, serializer, noCorruption, nil, key.enc, key.dec); err != nil {
							t.Errorf("RoundtripJWE: %v", err)
						}
					}
				}
			})
		}
	}
}

func TestX25519JWEParsedJWK(t *testing.T) {
	// Take the receiver key from RFC 8037 and roundtrip a message through its
	// JWK serialization to make sure the JWK path preserves the key.
	priv := newTestX25519Key(t)
	raw, err := (&JSONWebKey{Key: priv}).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var dec JSONWebKey
	if err := dec.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}

	pubJWK := dec.Public()
	enc, err := NewEncrypter(A128GCM, Recipient{Algorithm: ECDH_ES_A256KW, Key: pubJWK}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt([]byte("hello x25519"))
	if err != nil {
		t.Fatal(err)
	}

	msg, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEncrypted(msg, []KeyAlgorithm{ECDH_ES_A256KW}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	out, err := parsed.Decrypt(dec)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "hello x25519" {
		t.Errorf("got %q", out)
	}
}

func TestX25519EpkIsPublic(t *testing.T) {
	priv := newTestX25519Key(t)
	enc, err := NewEncrypter(A128GCM, Recipient{Algorithm: ECDH_ES, Key: priv.PublicKey()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	raw, err := json.Marshal(obj.protected)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	epk, ok := parsed["epk"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing epk: %s", raw)
	}
	if epk["kty"] != "OKP" || epk["crv"] != "X25519" {
		t.Errorf("unexpected epk: %v", epk)
	}
	if _, hasD := epk["d"]; hasD {
		t.Error("epk contains private key material")
	}
}

func TestX25519RejectsMismatchedKeys(t *testing.T) {
	xPriv := newTestX25519Key(t)
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// An X25519 private key must not decrypt a message encrypted to a NIST
	// curve key, and vice versa.
	enc, err := NewEncrypter(A128GCM, Recipient{Algorithm: ECDH_ES, Key: &ecTestKey256.PublicKey}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := obj.CompactSerialize()
	parsed, err := ParseEncrypted(msg, []KeyAlgorithm{ECDH_ES}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Decrypt(xPriv); err == nil {
		t.Error("X25519 key decrypted a NIST-curve message")
	}

	// A NIST-curve key must not decrypt an X25519 message.
	enc, err = NewEncrypter(A128GCM, Recipient{Algorithm: ECDH_ES, Key: xPriv.PublicKey()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err = enc.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	msg, _ = obj.CompactSerialize()
	parsed, err = ParseEncrypted(msg, []KeyAlgorithm{ECDH_ES}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Decrypt(ecTestKey256); err == nil {
		t.Error("NIST-curve key decrypted an X25519 message")
	}

	// A non-X25519 *ecdh.PublicKey (P-256) must be rejected as an ECDH-ES key.
	if _, err := NewEncrypter(A128GCM, Recipient{Algorithm: ECDH_ES, Key: p256.PublicKey()}, nil); err == nil {
		t.Error("accepted a P-256 crypto/ecdh key for ECDH-ES")
	}

	// A non-X25519 *ecdh.PrivateKey must be rejected as a decryption key.
	if _, err := newDecrypter(p256); err == nil {
		t.Error("accepted a P-256 crypto/ecdh private key as a decrypter")
	}
}

func TestX25519InvalidAlgorithms(t *testing.T) {
	priv := newTestX25519Key(t)

	// Key management algorithms outside the ECDH-ES family are unsupported.
	if _, err := newX25519Recipient("XYZ", priv.PublicKey()); err != ErrUnsupportedAlgorithm {
		t.Errorf("newX25519Recipient: got %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := newX25519Recipient(ECDH_ES, nil); err == nil {
		t.Error("newX25519Recipient accepted a nil key")
	}

	dec := x25519Decrypter{privateKey: priv}
	headers := epkHeaders(t, priv.PublicKey())
	if err := headers.set(headerAlgorithm, "XYZ"); err != nil {
		t.Fatal(err)
	}
	recipient := recipientInfo{}
	if _, err := dec.decryptKey(headers, &recipient, randomKeyGenerator{size: 16}); err != ErrUnsupportedAlgorithm {
		t.Errorf("decryptKey: got %v, want ErrUnsupportedAlgorithm", err)
	}
}

func TestX25519DecryptKeyErrors(t *testing.T) {
	priv := newTestX25519Key(t)
	generator := randomKeyGenerator{size: 16}
	recipient := recipientInfo{encryptedKey: []byte("not used")}

	dec := x25519Decrypter{privateKey: priv}

	// Missing epk.
	headers := rawHeader{}
	if err := headers.set(headerAlgorithm, ECDH_ES); err != nil {
		t.Fatal(err)
	}
	if _, err := dec.decryptKey(headers, &recipient, generator); err == nil ||
		err.Error() != "go-jose/go-jose: missing epk header" {
		t.Errorf("missing epk: got %v", err)
	}

	// Invalid epk.
	invalid := json.RawMessage("invalid")
	headers[headerEPK] = &invalid
	if _, err := dec.decryptKey(headers, &recipient, generator); err == nil ||
		err.Error() != "go-jose/go-jose: invalid epk header" {
		t.Errorf("invalid epk: got %v", err)
	}

	// epk with the wrong key type (NIST curve).
	if err := headers.set(headerEPK, &JSONWebKey{Key: &ecTestKey256.PublicKey}); err != nil {
		t.Fatal(err)
	}
	if _, err := dec.decryptKey(headers, &recipient, generator); err == nil ||
		err.Error() != "go-jose/go-jose: invalid epk header" {
		t.Errorf("wrong epk key type: got %v", err)
	}

	// Missing recipient.
	if _, err := dec.decryptKey(headers, nil, generator); err == nil {
		t.Error("accepted a nil recipient")
	}

	// Missing JWE Encrypted Key in key-wrap mode.
	epk := epkHeaders(t, priv.PublicKey())
	if err := epk.set(headerAlgorithm, ECDH_ES_A128KW); err != nil {
		t.Fatal(err)
	}
	empty := recipientInfo{}
	if _, err := dec.decryptKey(epk, &empty, generator); err == nil ||
		err.Error() != "go-jose/go-jose: missing JWE Encrypted Key" {
		t.Errorf("missing encrypted key: got %v", err)
	}
}

// epkHeaders builds a raw header carrying the given X25519 ephemeral public key.
func epkHeaders(t *testing.T, pub *ecdh.PublicKey) rawHeader {
	t.Helper()
	b, err := json.Marshal(&JSONWebKey{Key: pub})
	if err != nil {
		t.Fatal(err)
	}
	return rawHeader{headerEPK: makeRawMessage(b)}
}

func TestX25519DirectAgreementKeySize(t *testing.T) {
	// Direct key agreement must derive a key exactly the size of the content
	// encryption key, independent of the curve in use.
	xPriv := newTestX25519Key(t)
	ecPriv := ecTestKey256

	for _, tc := range []struct {
		name string
		enc  ContentEncryption
	}{
		{"A128GCM", A128GCM},
		{"A256GCM", A256GCM},
		{"A128CBC-HS256", A128CBC_HS256},
		{"A256CBC-HS512", A256CBC_HS512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cipher := getContentCipher(tc.enc)
			if cipher == nil {
				t.Fatal("no cipher")
			}
			want := cipher.keySize()

			xGen := x25519KeyGenerator{size: want, algID: string(tc.enc), publicKey: xPriv.PublicKey()}
			out, _, err := xGen.genKey()
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != want {
				t.Errorf("X25519 direct key length: got %d, want %d", len(out), want)
			}

			ecGen := ecKeyGenerator{size: want, algID: string(tc.enc), publicKey: &ecPriv.PublicKey}
			outEC, _, err := ecGen.genKey()
			if err != nil {
				t.Fatal(err)
			}
			if len(outEC) != want {
				t.Errorf("EC direct key length: got %d, want %d", len(outEC), want)
			}
		})
	}
}

func TestX25519KEKSizeIndependentOfMode(t *testing.T) {
	// The AES-KW KEK size must depend only on the key management algorithm,
	// not on the curve used for key agreement.
	xPriv := newTestX25519Key(t)
	cek := make([]byte, 16)

	for alg, want := range map[KeyAlgorithm]int{
		ECDH_ES_A128KW: 16,
		ECDH_ES_A192KW: 24,
		ECDH_ES_A256KW: 32,
	} {
		xEnc := x25519Encrypter{publicKey: xPriv.PublicKey()}
		if _, err := xEnc.encryptKey(cek, alg); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}

		// Verify the derived KEK size directly through the generator.
		gen := x25519KeyGenerator{size: want, algID: string(alg), publicKey: xPriv.PublicKey()}
		kek, _, err := gen.genKey()
		if err != nil {
			t.Fatal(err)
		}
		if len(kek) != want {
			t.Errorf("%s: KEK size %d, want %d", alg, len(kek), want)
		}
	}
}

func TestX25519DecryptRejectsLowOrderEpk(t *testing.T) {
	priv := newTestX25519Key(t)

	// json.Marshal of a low-order JWK is itself rejected; build the epk raw
	// message directly so the parsing path is what rejects it.
	epk := json.RawMessage(`{"kty":"OKP","crv":"X25519","x":"` +
		base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"}`)
	headers := rawHeader{headerEPK: &epk}
	if err := headers.set(headerAlgorithm, ECDH_ES); err != nil {
		t.Fatal(err)
	}
	if err := headers.set(headerEncryption, A128GCM); err != nil {
		t.Fatal(err)
	}

	dec := x25519Decrypter{privateKey: priv}
	recipient := recipientInfo{}
	if _, err := dec.decryptKey(headers, &recipient, randomKeyGenerator{size: 16}); err == nil {
		t.Error("decrypted with a low-order ephemeral key")
	}
}

func TestX25519RecipientRejectsLowOrder(t *testing.T) {
	lowOrder, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newX25519Recipient(ECDH_ES, lowOrder); err == nil {
		t.Error("accepted a low-order X25519 public key")
	}
	if _, err := NewEncrypter(A128GCM, Recipient{Algorithm: ECDH_ES, Key: lowOrder}, nil); err == nil {
		t.Error("encrypter accepted a low-order X25519 public key")
	}
}

func TestX25519RoundtripWithJWKS(t *testing.T) {
	priv := newTestX25519Key(t)
	jwks := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: "other", Key: newTestX25519Key(t).PublicKey()},
		{KeyID: "target", Key: priv},
	}}

	enc, err := NewEncrypter(A128GCM, Recipient{
		Algorithm: ECDH_ES,
		Key:       JSONWebKey{KeyID: "target", Key: priv.PublicKey()},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt([]byte("jwks payload"))
	if err != nil {
		t.Fatal(err)
	}
	msg, _ := obj.CompactSerialize()

	parsed, err := ParseEncrypted(msg, []KeyAlgorithm{ECDH_ES}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	out, err := parsed.Decrypt(jwks)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "jwks payload" {
		t.Errorf("got %q", out)
	}
}

func TestX25519MultiRecipient(t *testing.T) {
	// ECDH-ES+A*KW works in multi-recipient mode, including alongside other
	// key types; ECDH-ES (direct) must remain unsupported there.
	xPriv := newTestX25519Key(t)

	enc, err := NewMultiEncrypter(A128GCM, []Recipient{
		{Algorithm: ECDH_ES_A256KW, Key: xPriv.PublicKey()},
		{Algorithm: A128KW, Key: make([]byte, 16)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := enc.Encrypt([]byte("multi"))
	if err != nil {
		t.Fatal(err)
	}
	msg := obj.FullSerialize()
	parsed, err := ParseEncrypted(msg, []KeyAlgorithm{ECDH_ES_A256KW, A128KW}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatal(err)
	}
	_, _, out, err := parsed.DecryptMulti(xPriv)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "multi" {
		t.Errorf("got %q", out)
	}

	// Direct ECDH-ES is not allowed with multiple recipients.
	if _, err := NewMultiEncrypter(A128GCM, []Recipient{
		{Algorithm: ECDH_ES, Key: xPriv.PublicKey()},
		{Algorithm: A128KW, Key: make([]byte, 16)},
	}, nil); err == nil {
		t.Error("accepted direct ECDH-ES in multi-recipient mode")
	}
}

func TestX25519PrivateKeyNotAcceptedForEncryption(t *testing.T) {
	// A private key must not be usable as an encryption recipient key.
	xPriv := newTestX25519Key(t)
	if _, err := NewEncrypter(A128GCM, Recipient{Algorithm: ECDH_ES, Key: xPriv}, nil); err == nil {
		t.Error("accepted a private X25519 key as an encryption key")
	}
	if _, err := NewEncrypter(A128GCM, Recipient{Algorithm: ECDH_ES_A128KW, Key: xPriv}, nil); err == nil {
		t.Error("accepted a private X25519 key for ECDH-ES+A128KW")
	}
}

func TestX25519PrivateEPKRejected(t *testing.T) {
	priv := newTestX25519Key(t)

	// The "epk" header must be a public key; private key material in it has to
	// be rejected before parsing.
	raw := json.RawMessage(`{"kty":"OKP","crv":"X25519","x":"` +
		base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()) +
		`","d":"` + base64.RawURLEncoding.EncodeToString(priv.Bytes()) + `"}`)
	headers := rawHeader{headerEPK: &raw}
	if _, err := headers.getEPK(); err == nil || !strings.Contains(err.Error(), "private parameters") {
		t.Errorf("expected private parameters error, got %v", err)
	}
}

func TestX25519AlgorithmMismatchWithKeyType(t *testing.T) {
	// Signing algorithms must not be usable for encryption, and the X25519
	// key must be rejected where a signing key is expected.
	xPriv := newTestX25519Key(t)
	if _, err := NewSigner(SigningKey{Algorithm: EdDSA, Key: xPriv}, nil); err == nil {
		t.Error("accepted an X25519 key as a signing key")
	}

	// Conversely, Ed25519 keys must not be usable for ECDH-ES.
	if _, err := NewEncrypter(A128GCM, Recipient{Algorithm: ECDH_ES, Key: ed25519PublicKey}, nil); err == nil {
		t.Error("accepted an Ed25519 key for ECDH-ES")
	}
}

func TestX25519UnsupportedKeyType(t *testing.T) {
	// A JWK with an unknown OKP curve must return ErrUnsupportedKeyType.
	var jwk JSONWebKey
	err := jwk.UnmarshalJSON([]byte(`{"kty":"OKP","crv":"X448","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`))
	if !errors.Is(err, ErrUnsupportedKeyType) {
		t.Errorf("expected ErrUnsupportedKeyType, got %v", err)
	}
}
