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

// This file holds end-to-end regression tests that chain three stages of JWS
// verification together:
//
//  1. importing a key that arrives in a header the caller does not control,
//  2. selecting a key from a JWK Set the caller does control,
//  3. verifying one or more signatures that share a payload.
//
// Two boundaries are kept strictly apart:
//
//   - Syntactic validity of a key imported from an untrusted header never
//     conveys authorization. Private key material and structurally invalid
//     public keys are rejected at parse time, and a public key embedded in a
//     message is never used as the verification key unless the caller passes
//     it explicitly.
//   - The key the caller supplies is the only source of trust. A signature
//     authenticates the payload only if it verifies under that key, with an
//     algorithm admitted both by the caller's parse-time allowlist and by the
//     key type actually used to verify.
//
// The tests deliberately cover each stage both in isolation and chained, so a
// regression in key import, in JWKS selection, or in multi-signature
// verification cannot hide behind the other stages. All key material is
// generated or derived locally in this file; no external fixtures are read.
//
// Where the current implementation has a documented, security-relevant
// behavior (for example, that JWKS selection returns only the first matching
// "kid" and does not fall through to later duplicates), the test states that
// behavior explicitly rather than smoothing it over.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4/json"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func trustIsolationECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	return key
}

func trustIsolationEdKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return pub, priv
}

func trustIsolationBytes(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return b
}

func trustIsolationJWKBytes(t *testing.T, key interface{}, kid string) []byte {
	t.Helper()
	return trustIsolationBytes(t, JSONWebKey{Key: key, KeyID: kid})
}

// trustIsolationMessages builds the three JWS serializations around a raw
// protected header. The signature bytes are not validated at parse time, so
// arbitrary bytes are sufficient for import-boundary tests.
func trustIsolationMessages(t *testing.T, protected, payload, signature []byte) map[string]string {
	t.Helper()
	p := base64.RawURLEncoding.EncodeToString(protected)
	pl := base64.RawURLEncoding.EncodeToString(payload)
	s := base64.RawURLEncoding.EncodeToString(signature)
	return map[string]string{
		"compact":   p + "." + pl + "." + s,
		"flattened": `{"payload":"` + pl + `","protected":"` + p + `","signature":"` + s + `"}`,
		"general":   `{"payload":"` + pl + `","signatures":[{"protected":"` + p + `","signature":"` + s + `"}]}`,
	}
}

// trustIsolationUnprotectedMessages builds flattened and general
// serializations with the same key placed in the unprotected header. Compact
// serialization cannot carry an unprotected header.
func trustIsolationUnprotectedMessages(t *testing.T, alg SignatureAlgorithm, jwk, payload, signature []byte) map[string]string {
	t.Helper()
	algJSON := json.RawMessage(`"` + alg + `"`)
	protected := trustIsolationBytes(t, rawHeader{headerAlgorithm: &algJSON})
	unprotected := rawHeader{headerJWK: makeRawMessage(jwk)}
	return map[string]string{
		"flattened": string(trustIsolationBytes(t, rawJSONWebSignature{
			Payload:   newBuffer(payload),
			Protected: newBuffer(protected),
			Header:    &unprotected,
			Signature: newBuffer(signature),
		})),
		"general": string(trustIsolationBytes(t, rawJSONWebSignature{
			Payload: newBuffer(payload),
			Signatures: []rawSignatureInfo{{
				Protected: newBuffer(protected),
				Header:    &unprotected,
				Signature: newBuffer(signature),
			}},
		})),
	}
}

// trustIsolationRawSignature extracts a single signature from a signed object
// so it can be recombined into a general-serialization message.
func trustIsolationRawSignature(t *testing.T, obj *JSONWebSignature) rawSignatureInfo {
	t.Helper()
	var raw rawJSONWebSignature
	if err := json.Unmarshal([]byte(obj.FullSerialize()), &raw); err != nil {
		t.Fatalf("unmarshal signed object: %v", err)
	}
	if len(raw.Signatures) == 1 {
		return raw.Signatures[0]
	}
	return rawSignatureInfo{
		Protected: raw.Protected,
		Header:    raw.Header,
		Signature: raw.Signature,
	}
}

// trustIsolationGeneral combines independently signed objects into one
// general-serialization message sharing a single payload.
func trustIsolationGeneral(t *testing.T, payload []byte, objs ...*JSONWebSignature) string {
	t.Helper()
	sigs := make([]rawSignatureInfo, 0, len(objs))
	for _, obj := range objs {
		sigs = append(sigs, trustIsolationRawSignature(t, obj))
	}
	return string(trustIsolationBytes(t, rawJSONWebSignature{
		Payload:    newBuffer(payload),
		Signatures: sigs,
	}))
}

// trustIsolationSign signs payload with key and optional kid, returning the
// signed object. A nil kid inserts no "kid" header.
func trustIsolationSign(t *testing.T, alg SignatureAlgorithm, key interface{}, kid string, opts *SignerOptions, payload []byte) *JSONWebSignature {
	t.Helper()
	var signingKey interface{} = key
	if kid != "" {
		signingKey = &JSONWebKey{KeyID: kid, Key: key}
	}
	signer, err := NewSigner(SigningKey{Algorithm: alg, Key: signingKey}, opts)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return obj
}

// trustIsolationParseAndVerify parses a serialized JWS with the given
// allowlist and runs a single-signature Verify against key.
func trustIsolationParseAndVerify(t *testing.T, msg string, allowed []SignatureAlgorithm, key interface{}) (*JSONWebSignature, []byte, error) {
	t.Helper()
	obj, err := ParseSigned(msg, allowed)
	if err != nil {
		return nil, nil, err
	}
	out, err := obj.Verify(key)
	return obj, out, err
}

// ---------------------------------------------------------------------------
// Area 1: key import from an untrusted header vs. caller-supplied trust
// ---------------------------------------------------------------------------

// TestTrustIsolationHeaderKeyImportBoundary pins the import boundary. Anything
// that is not a usable public key is rejected while parsing a header the caller
// does not control, in every serialization and whether the key sits in the
// protected or the unprotected header. A valid public key is admitted, but
// admission alone is not authorization; that is covered separately below.
func TestTrustIsolationHeaderKeyImportBoundary(t *testing.T) {
	ecKey := trustIsolationECKey(t)
	edPub, edPriv := trustIsolationEdKeys(t)

	// P-256 generator coordinates, used to build keys that are wrong in a
	// specific way rather than in every way at once.
	gx := fromHexBytes("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
	gy := fromHexBytes("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")

	offCurveX := make([]byte, 32)
	offCurveY := make([]byte, 32)
	offCurveX[0], offCurveY[0] = 1, 1

	tooLargeModulus := new(big.Int).Lsh(big.NewInt(1), uint(MaxRSAModulusBits))

	type testCase struct {
		name      string
		alg       SignatureAlgorithm
		jwk       []byte
		wantErr   string // substring of the parse error
		wantErrIs error  // sentinel matched with errors.Is, if set
		// unprotected also runs the case with the JWK in the unprotected
		// header, which carries the same lack of trust.
		unprotected bool
	}

	privateECJWK := trustIsolationJWKBytes(t, ecKey, "")
	privateEdJWK := trustIsolationJWKBytes(t, edPriv, "")
	privateRSAJWK, err := fromRsaPrivateKey(rsaTestKey)
	if err != nil {
		t.Fatalf("encode RSA private key: %v", err)
	}
	privateRSAJWKBytes := trustIsolationBytes(t, privateRSAJWK)
	symmetricJWK := trustIsolationBytes(t, rawJSONWebKey{
		Kty: "oct",
		K:   newBuffer([]byte("untrusted-shared-secret")),
	})

	testCases := []testCase{
		// Valid public keys are the control group.
		{name: "valid EC public key", alg: ES256, jwk: trustIsolationJWKBytes(t, &ecKey.PublicKey, "")},
		{name: "valid Ed25519 public key", alg: EdDSA, jwk: trustIsolationJWKBytes(t, edPub, "")},
		{name: "valid RSA public key", alg: RS256, jwk: trustIsolationJWKBytes(t, &rsaTestKey.PublicKey, "")},

		// Private key material of every supported family, plus a shared secret.
		{name: "EC private key material", alg: ES256, jwk: privateECJWK, wantErr: "private parameters", unprotected: true},
		{name: "Ed25519 private key material", alg: EdDSA, jwk: privateEdJWK, wantErr: "private parameters", unprotected: true},
		{name: "RSA private key material", alg: RS256, jwk: privateRSAJWKBytes, wantErr: "private parameters", unprotected: true},
		{name: "symmetric key material", alg: HS256, jwk: symmetricJWK, wantErr: "private parameters", unprotected: true},

		// Structurally invalid public keys.
		{name: "EC point not on curve", alg: ES256, jwk: trustIsolationBytes(t, rawJSONWebKey{
			Kty: "EC", Crv: "P-256", X: newBuffer(offCurveX), Y: newBuffer(offCurveY),
		}), wantErr: "not on declared curve"},
		{name: "EC x wrong length", alg: ES256, jwk: trustIsolationBytes(t, rawJSONWebKey{
			Kty: "EC", Crv: "P-256", X: newBuffer([]byte{1}), Y: newBuffer(gy),
		}), wantErr: "wrong length for x"},
		{name: "EC y wrong length", alg: ES256, jwk: trustIsolationBytes(t, rawJSONWebKey{
			Kty: "EC", Crv: "P-256", X: newBuffer(gx), Y: newBuffer([]byte{1}),
		}), wantErr: "wrong length for y"},
		{name: "Ed25519 low-order point", alg: EdDSA, jwk: trustIsolationBytes(t, rawJSONWebKey{
			Kty: "OKP", Crv: "Ed25519", X: newBuffer(make([]byte, ed25519.PublicKeySize)),
		}), wantErr: "low-order point"},
		{name: "Ed25519 short key", alg: EdDSA, jwk: trustIsolationBytes(t, rawJSONWebKey{
			Kty: "OKP", Crv: "Ed25519", X: newBuffer([]byte{1}),
		}), wantErr: "wrong length for x"},
		{name: "unsupported OKP curve", alg: EdDSA, jwk: trustIsolationBytes(t, rawJSONWebKey{
			Kty: "OKP", Crv: "X25519", X: newBuffer(make([]byte, 32)),
		}), wantErrIs: ErrUnsupportedKeyType},
		{name: "unknown key type", alg: ES256, jwk: []byte(`{"kty":"XXX"}`), wantErrIs: ErrUnsupportedKeyType},
		{name: "RSA modulus over limit", alg: RS256, jwk: trustIsolationBytes(t, rawJSONWebKey{
			Kty: "RSA", N: newBuffer(tooLargeModulus.Bytes()), E: newBuffer([]byte{1, 0, 1}),
		}), wantErrIs: ErrUnsupportedKeyType},
		{name: "RSA missing modulus", alg: RS256, jwk: []byte(`{"kty":"RSA","e":"AQAB"}`), wantErr: "missing n/e values"},
		{name: "RSA invalid exponent", alg: RS256, jwk: trustIsolationBytes(t, rawJSONWebKey{
			Kty: "RSA", N: newBuffer(rsaTestKey.N.Bytes()), E: newBuffer([]byte{0}),
		}), wantErr: "bad e value"},
	}

	payload := []byte("import boundary payload")
	signature := make([]byte, 64)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			algJSON := json.RawMessage(`"` + tc.alg + `"`)
			jwkJSON := json.RawMessage(tc.jwk)
			protected := rawHeader{headerAlgorithm: &algJSON, headerJWK: &jwkJSON}
			protectedJSON := trustIsolationBytes(t, protected)

			wantErr := tc.wantErr != ""
			wantErrIs := tc.wantErrIs != nil

			for serialization, msg := range trustIsolationMessages(t, protectedJSON, payload, signature) {
				obj, err := ParseSigned(msg, []SignatureAlgorithm{tc.alg})
				if !wantErr && !wantErrIs {
					if err != nil {
						t.Fatalf("%s: valid public key must be admitted: %v", serialization, err)
					}
					embedded := obj.Signatures[0].Header.JSONWebKey
					if embedded == nil || !embedded.IsPublic() {
						t.Fatalf("%s: admitted key must be exposed as a public JWK", serialization)
					}
					if !embedded.Valid() {
						t.Fatalf("%s: admitted key must be structurally valid", serialization)
					}
					continue
				}

				if err == nil {
					t.Fatalf("%s: expected parse rejection, message was admitted", serialization)
				}
				if obj != nil {
					t.Fatalf("%s: rejected message must not yield a parsed object", serialization)
				}
				if wantErrIs && !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("%s: error %q does not match %v", serialization, err, tc.wantErrIs)
				}
				if !wantErrIs && !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("%s: error %q does not contain %q", serialization, err, tc.wantErr)
				}
			}

			// A private key placed in the unprotected header is just as
			// untrusted as one in the protected header and must be rejected.
			if tc.unprotected {
				for serialization, msg := range trustIsolationUnprotectedMessages(t, tc.alg, tc.jwk, payload, signature) {
					_, err := ParseSigned(msg, []SignatureAlgorithm{tc.alg})
					if err == nil || !strings.Contains(err.Error(), "private parameters") {
						t.Fatalf("%s (unprotected): expected private-parameter rejection, got %v", serialization, err)
					}
				}
			}
		})
	}
}

// TestTrustIsolationEmbeddedPublicKeyIsNotATrustSource proves that a public key
// carried in the message can make a signature self-consistent without ever
// becoming the caller's trust anchor. The caller's key alone decides.
func TestTrustIsolationEmbeddedPublicKeyIsNotATrustSource(t *testing.T) {
	payload := []byte("embedded key is not a trust anchor")

	trustedKey := trustIsolationECKey(t)
	attackerKey := trustIsolationECKey(t)

	t.Run("trusted signature with an embedded public key", func(t *testing.T) {
		obj := trustIsolationSign(t, ES256, trustedKey, "", &SignerOptions{EmbedJWK: true}, payload)
		parsed, err := ParseSigned(obj.FullSerialize(), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		embedded := parsed.Signatures[0].Header.JSONWebKey
		if embedded == nil || !embedded.IsPublic() {
			t.Fatal("expected the public JWK to be embedded")
		}

		out, err := parsed.Verify(&trustedKey.PublicKey)
		if err != nil {
			t.Fatalf("caller-supplied trusted key must verify: %v", err)
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}

		if _, err := parsed.Verify(&attackerKey.PublicKey); !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("foreign key must not verify, got %v", err)
		}

		// A JWKS the caller trusts is still consulted by "kid" only. Because
		// the message carries no "kid", the embedded JWK must not be used as a
		// fallback selection source.
		jwks := &JSONWebKeySet{Keys: []JSONWebKey{{KeyID: "unrelated", Key: &attackerKey.PublicKey}}}
		if _, err := parsed.Verify(jwks); !errors.Is(err, ErrJWKSKidNotFound) {
			t.Fatalf("embedded JWK must not satisfy JWKS selection, got %v", err)
		}
	})

	t.Run("attacker signature is self-consistent but not trusted", func(t *testing.T) {
		obj := trustIsolationSign(t, ES256, attackerKey, "", &SignerOptions{EmbedJWK: true}, payload)
		parsed, err := ParseSigned(obj.FullSerialize(), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}

		// The embedded key does verify the attacker's own signature: that
		// proves internal consistency, nothing more.
		if _, err := parsed.Verify(parsed.Signatures[0].Header.JSONWebKey); err != nil {
			t.Fatalf("attacker signature must verify under the embedded attacker key: %v", err)
		}

		// The caller's key is the trust decision. It must reject the message.
		if _, err := parsed.Verify(&trustedKey.PublicKey); !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("caller-supplied trusted key must reject the attacker signature, got %v", err)
		}
	})
}

// TestTrustIsolationEmbeddedJWKCannotSatisfyJWKSSelection chains import and
// selection: the attacker embeds its own public key and also labels the
// signature with a "kid" that exists in the caller's JWKS. The embedded key
// must not be used, and selection must land on the caller's key, under which
// the attacker's signature fails.
func TestTrustIsolationEmbeddedJWKCannotSatisfyJWKSSelection(t *testing.T) {
	payload := []byte("embedded key vs trusted JWKS")

	trustedKey := trustIsolationECKey(t)
	attackerKey := trustIsolationECKey(t)
	const sharedKid = "trusted-kid"

	attackerSigned := trustIsolationSign(t, ES256, attackerKey, "", &SignerOptions{EmbedJWK: true}, payload)
	// Add the unprotected "kid" after signing: the signature covers only the
	// protected header, so it stays valid, and the attacker controls this
	// header completely.
	attackerSigned.Signatures[0].header = &rawHeader{
		headerKeyID: makeRawMessage(trustIsolationBytes(t, sharedKid)),
	}
	msg := attackerSigned.FullSerialize()

	jwks := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: sharedKid, Key: &trustedKey.PublicKey},
	}}

	parsed, err := ParseSigned(msg, []SignatureAlgorithm{ES256})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Signatures[0].Header.JSONWebKey == nil {
		t.Fatal("expected the attacker JWK to remain embedded in the protected header")
	}
	if parsed.Signatures[0].Header.KeyID != sharedKid {
		t.Fatalf("unprotected kid not merged, got %q", parsed.Signatures[0].Header.KeyID)
	}

	// Selection picks the caller's trusted key. The embedded attacker key is
	// not consulted, so verification must fail.
	if _, err := parsed.Verify(jwks); !errors.Is(err, ErrCryptoFailure) {
		t.Fatalf("attacker signature must not authenticate under the trusted JWKS entry, got %v", err)
	}
	if _, err := parsed.Verify(&trustedKey.PublicKey); !errors.Is(err, ErrCryptoFailure) {
		t.Fatalf("attacker signature must not authenticate under the trusted key, got %v", err)
	}

	// Chain into multi-signature verification: a genuine signature from the
	// trusted key is appended and must still be the one that authenticates.
	trustedSigned := trustIsolationSign(t, ES256, trustedKey, sharedKid, nil, payload)
	merged, err := ParseSigned(trustIsolationGeneral(t, payload, attackerSigned, trustedSigned), []SignatureAlgorithm{ES256})
	if err != nil {
		t.Fatalf("parse merged message: %v", err)
	}
	idx, sig, out, err := merged.VerifyMulti(jwks)
	if err != nil {
		t.Fatalf("trusted signature at index 1 must verify: %v", err)
	}
	if idx != 1 {
		t.Fatalf("verified index = %d, want 1", idx)
	}
	if sig.Header.KeyID != sharedKid {
		t.Fatalf("verified kid = %q, want %q", sig.Header.KeyID, sharedKid)
	}
	if !bytes.Equal(sig.Signature, merged.Signatures[idx].Signature) {
		t.Fatal("returned signature does not belong to the verified entry")
	}
	if !bytes.Equal(out, payload) {
		t.Fatal("verified payload mismatch")
	}
}

// TestTrustIsolationProtectedAlgorithmWins shows that the algorithm the caller
// admits is the one in the integrity-protected header. An attacker editing the
// unprotected header cannot relabel the algorithm to escape the allowlist.
func TestTrustIsolationProtectedAlgorithmWins(t *testing.T) {
	payload := []byte("protected alg precedence")
	key := trustIsolationECKey(t)

	obj := trustIsolationSign(t, ES256, key, "kid", nil, payload)
	// Attacker-controlled unprotected alg disagreeing with the protected one.
	obj.Signatures[0].header = &rawHeader{
		headerAlgorithm: makeRawMessage(trustIsolationBytes(t, "RS256")),
	}

	// Both labels are allowed, so the parse succeeds either way. The merged
	// header must resolve to the protected value: the unprotected "alg" is not
	// integrity protected and must not override it.
	parsed, err := ParseSigned(obj.FullSerialize(), []SignatureAlgorithm{ES256, RS256})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := parsed.Signatures[0].Header.Algorithm; got != string(ES256) {
		t.Fatalf("merged alg = %q, want %q", got, ES256)
	}

	out, err := parsed.Verify(&key.PublicKey)
	if err != nil {
		t.Fatalf("trusted key must verify the intact signature: %v", err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatal("verified payload mismatch")
	}

	// The relabelled algorithm cannot be smuggled past the key type either.
	if _, err := parsed.Verify(&rsaTestKey.PublicKey); !errors.Is(err, ErrCryptoFailure) {
		t.Fatalf("RSA key must not verify an ES256 signature, got %v", err)
	}
}

// TestTrustIsolationAlgorithmBoundByAllowlistAndKeyType checks that the usable
// algorithm is the intersection of the caller's parse-time allowlist and what
// the actual verification key can perform.
func TestTrustIsolationAlgorithmBoundByAllowlistAndKeyType(t *testing.T) {
	payload := []byte("algorithm constraint payload")

	ecKey := trustIsolationECKey(t)

	t.Run("allowlist rejects a disallowed algorithm", func(t *testing.T) {
		obj := trustIsolationSign(t, ES256, ecKey, "", nil, payload)
		compact, err := obj.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}

		_, err = ParseSigned(compact, []SignatureAlgorithm{RS256, EdDSA})
		var unexpected *ErrUnexpectedSignatureAlgorithm
		if !errors.As(err, &unexpected) {
			t.Fatalf("expected ErrUnexpectedSignatureAlgorithm, got %v", err)
		}
		if unexpected.Got != ES256 {
			t.Fatalf("reported algorithm = %q, want ES256", unexpected.Got)
		}
	})

	t.Run("allowlist applies to every signature", func(t *testing.T) {
		good := trustIsolationRawSignature(t, trustIsolationSign(t, ES256, ecKey, "", nil, payload))
		badAlg := json.RawMessage(`"HS256"`)
		bad := rawSignatureInfo{
			Protected: newBuffer(trustIsolationBytes(t, rawHeader{headerAlgorithm: &badAlg})),
			Signature: newBuffer([]byte("irrelevant")),
		}

		for name, sigs := range map[string][]rawSignatureInfo{
			"disallowed second": {good, bad},
			"disallowed first":  {bad, good},
		} {
			msg := string(trustIsolationBytes(t, rawJSONWebSignature{
				Payload:    newBuffer(payload),
				Signatures: sigs,
			}))
			_, err := ParseSigned(msg, []SignatureAlgorithm{ES256})
			var unexpected *ErrUnexpectedSignatureAlgorithm
			if !errors.As(err, &unexpected) || unexpected.Got != HS256 {
				t.Fatalf("%s: expected whole-message rejection for HS256, got %v", name, err)
			}
		}
	})

	t.Run("key type cannot perform the header algorithm", func(t *testing.T) {
		obj := trustIsolationSign(t, RS256, rsaTestKey, "", nil, payload)
		parsed, err := ParseSigned(obj.FullSerialize(), []SignatureAlgorithm{RS256, ES256})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parsed.Verify(&ecKey.PublicKey); !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("EC key must not verify RS256, got %v", err)
		}
		out, err := parsed.Verify(&rsaTestKey.PublicKey)
		if err != nil {
			t.Fatalf("RSA key must verify RS256: %v", err)
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}
	})

	t.Run("curve must match the header algorithm", func(t *testing.T) {
		// An ES384 signature header with a P-256 key: the allowlist admits
		// ES384, but the key type cannot perform it.
		prot := json.RawMessage(`"ES384"`)
		protected := trustIsolationBytes(t, rawHeader{headerAlgorithm: &prot})
		msg := base64.RawURLEncoding.EncodeToString(protected) + "." +
			base64.RawURLEncoding.EncodeToString(payload) + "." +
			base64.RawURLEncoding.EncodeToString(make([]byte, 96))

		_, _, err := trustIsolationParseAndVerify(t, msg, []SignatureAlgorithm{ES384}, &ecKey.PublicKey)
		if !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("P-256 key must not perform ES384, got %v", err)
		}
	})

	t.Run("asymmetric key cannot act as an HMAC secret", func(t *testing.T) {
		macKey := bytes.Repeat([]byte{0x11}, 32)
		obj := trustIsolationSign(t, HS256, macKey, "", nil, payload)
		parsed, err := ParseSigned(obj.FullSerialize(), []SignatureAlgorithm{HS256, RS256})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parsed.Verify(&rsaTestKey.PublicKey); !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("RSA public key must not verify HS256, got %v", err)
		}
	})

	t.Run("HMAC key material and size bound verification", func(t *testing.T) {
		macKey := bytes.Repeat([]byte{0x11}, 32)
		obj := trustIsolationSign(t, HS256, macKey, "", nil, payload)
		parsed, err := ParseSigned(obj.FullSerialize(), []SignatureAlgorithm{HS256})
		if err != nil {
			t.Fatal(err)
		}

		out, err := parsed.Verify(macKey)
		if err != nil {
			t.Fatalf("matching HMAC key must verify: %v", err)
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}

		// Correct algorithm, wrong secret.
		if _, err := parsed.Verify(bytes.Repeat([]byte{0x22}, 32)); !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("wrong HMAC secret must not verify, got %v", err)
		}
		// Correct secret, too short for HS256's output size.
		if _, err := parsed.Verify(bytes.Repeat([]byte{0x11}, 16)); !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("undersized HMAC key must not verify, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Area 2: multi-signature contracts over a shared payload
// ---------------------------------------------------------------------------

// TestTrustIsolationMultiSigSkippableFailures covers per-signature failures
// that must not discard a later genuine signature, and that the returned index
// and signature belong to the signature that actually verified.
func TestTrustIsolationMultiSigSkippableFailures(t *testing.T) {
	payload := []byte("multi-signature shared payload")

	goodKey := trustIsolationECKey(t)
	unknownKey := trustIsolationECKey(t)

	t.Run("unmatched kid is skipped, later signature verifies", func(t *testing.T) {
		first := trustIsolationSign(t, ES256, goodKey, "kid-unknown", nil, payload)
		second := trustIsolationSign(t, ES256, goodKey, "kid-good", nil, payload)
		parsed, err := ParseSigned(trustIsolationGeneral(t, payload, first, second), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}

		jwks := &JSONWebKeySet{Keys: []JSONWebKey{{KeyID: "kid-good", Key: &goodKey.PublicKey}}}
		idx, sig, out, err := parsed.VerifyMulti(jwks)
		if err != nil {
			t.Fatalf("later genuine signature must not be discarded: %v", err)
		}
		if idx != 1 {
			t.Fatalf("verified index = %d, want 1", idx)
		}
		if sig.Header.KeyID != "kid-good" {
			t.Fatalf("verified kid = %q, want \"kid-good\"", sig.Header.KeyID)
		}
		if !bytes.Equal(sig.Signature, parsed.Signatures[idx].Signature) {
			t.Fatal("returned signature does not belong to the verified entry")
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}
	})

	t.Run("corrupt signature is skipped, later signature verifies", func(t *testing.T) {
		first := trustIsolationSign(t, ES256, goodKey, "kid-first", nil, payload)
		second := trustIsolationSign(t, ES256, goodKey, "kid-second", nil, payload)
		var merged rawJSONWebSignature
		if err := json.Unmarshal([]byte(trustIsolationGeneral(t, payload, first, second)), &merged); err != nil {
			t.Fatal(err)
		}
		merged.Signatures[0].Signature = newBuffer([]byte("definitely not the signature"))

		parsed, err := ParseSigned(string(trustIsolationBytes(t, merged)), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}
		idx, sig, _, err := parsed.VerifyMulti(&goodKey.PublicKey)
		if err != nil {
			t.Fatalf("corrupt signature at index 0 must not suppress index 1: %v", err)
		}
		if idx != 1 || sig.Header.KeyID != "kid-second" {
			t.Fatalf("got index %d kid %q, want index 1 kid \"kid-second\"", idx, sig.Header.KeyID)
		}
	})

	t.Run("unsupported protected crit is skipped, later signature verifies", func(t *testing.T) {
		opts := (&SignerOptions{}).WithCritical("unknown-extension")
		first := trustIsolationSign(t, ES256, goodKey, "kid-crit", opts, payload)
		second := trustIsolationSign(t, ES256, goodKey, "kid-plain", nil, payload)

		parsed, err := ParseSigned(trustIsolationGeneral(t, payload, first, second), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}
		idx, sig, out, err := parsed.VerifyMulti(&goodKey.PublicKey)
		if err != nil {
			t.Fatalf("unsupported crit at index 0 must not suppress index 1: %v", err)
		}
		if idx != 1 || sig.Header.KeyID != "kid-plain" {
			t.Fatalf("got index %d kid %q, want index 1 kid \"kid-plain\"", idx, sig.Header.KeyID)
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}
	})

	t.Run("unprotected crit is skipped, later signature verifies", func(t *testing.T) {
		first := trustIsolationSign(t, ES256, goodKey, "kid-unprotected-crit", nil, payload)
		first.Signatures[0].header = &rawHeader{
			headerCritical: makeRawMessage(trustIsolationBytes(t, []string{"unknown-extension"})),
		}
		second := trustIsolationSign(t, ES256, goodKey, "kid-plain", nil, payload)

		parsed, err := ParseSigned(trustIsolationGeneral(t, payload, first, second), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}
		idx, sig, _, err := parsed.VerifyMulti(&goodKey.PublicKey)
		if err != nil {
			t.Fatalf("unprotected crit at index 0 must not suppress index 1: %v", err)
		}
		if idx != 1 || sig.Header.KeyID != "kid-plain" {
			t.Fatalf("got index %d kid %q, want index 1 kid \"kid-plain\"", idx, sig.Header.KeyID)
		}
	})

	t.Run("identity never comes from an unverified candidate", func(t *testing.T) {
		first := trustIsolationSign(t, ES256, unknownKey, "kid-a", nil, payload)
		second := trustIsolationSign(t, ES256, goodKey, "kid-b", nil, payload)
		parsed, err := ParseSigned(trustIsolationGeneral(t, payload, first, second), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}

		// Both signatures are visible, but only the second authenticates under
		// the trusted key. The returned identity must be the second one.
		idx, sig, out, err := parsed.VerifyMulti(&goodKey.PublicKey)
		if err != nil {
			t.Fatalf("trusted key must verify the second signature: %v", err)
		}
		if idx != 1 || sig.Header.KeyID != "kid-b" {
			t.Fatalf("got index %d kid %q, want index 1 kid \"kid-b\"", idx, sig.Header.KeyID)
		}
		if !bytes.Equal(sig.Signature, parsed.Signatures[idx].Signature) {
			t.Fatal("returned signature does not belong to the verified entry")
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}
	})
}

// TestTrustIsolationMultiSigTotalFailure checks the "no trusted payload"
// contract when every signature fails, for both selection failures and
// cryptographic failures.
func TestTrustIsolationMultiSigTotalFailure(t *testing.T) {
	payload := []byte("all signatures fail payload")

	signingKey := trustIsolationECKey(t)
	otherKey := trustIsolationECKey(t)

	first := trustIsolationSign(t, ES256, signingKey, "kid-a", nil, payload)
	second := trustIsolationSign(t, ES256, signingKey, "kid-b", nil, payload)
	parsed, err := ParseSigned(trustIsolationGeneral(t, payload, first, second), []SignatureAlgorithm{ES256})
	if err != nil {
		t.Fatal(err)
	}

	assertNoTrustedPayload := func(t *testing.T, idx int, sig Signature, out []byte, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected failure when no signature authenticates")
		}
		if idx != -1 {
			t.Fatalf("failure index = %d, want -1", idx)
		}
		if out != nil {
			t.Fatalf("no payload may be returned on total failure, got %q", out)
		}
		if sig.Header.KeyID != "" || sig.Signature != nil {
			t.Fatal("no signature identity may be returned on total failure")
		}
	}

	t.Run("no matching kid anywhere", func(t *testing.T) {
		jwks := &JSONWebKeySet{Keys: []JSONWebKey{{KeyID: "kid-unknown", Key: &signingKey.PublicKey}}}
		idx, sig, out, err := parsed.VerifyMulti(jwks)
		assertNoTrustedPayload(t, idx, sig, out, err)
	})

	t.Run("wrong key for every signature", func(t *testing.T) {
		idx, sig, out, err := parsed.VerifyMulti(&otherKey.PublicKey)
		if !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure, got %v", err)
		}
		assertNoTrustedPayload(t, idx, sig, out, err)
	})

	t.Run("every signature value corrupted", func(t *testing.T) {
		var merged rawJSONWebSignature
		if err := json.Unmarshal([]byte(trustIsolationGeneral(t, payload, first, second)), &merged); err != nil {
			t.Fatal(err)
		}
		for i := range merged.Signatures {
			merged.Signatures[i].Signature = newBuffer([]byte("corrupted"))
		}
		corrupted, err := ParseSigned(string(trustIsolationBytes(t, merged)), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}
		idx, sig, out, err := corrupted.VerifyMulti(&signingKey.PublicKey)
		if !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure, got %v", err)
		}
		assertNoTrustedPayload(t, idx, sig, out, err)
	})

	t.Run("single Verify refuses a multi-signature message", func(t *testing.T) {
		_, _, err := trustIsolationParseAndVerify(t, trustIsolationGeneral(t, payload, first, second), []SignatureAlgorithm{ES256}, &signingKey.PublicKey)
		if err == nil || !strings.Contains(err.Error(), "too many signatures") {
			t.Fatalf("expected too-many-signatures error, got %v", err)
		}
	})

	// DetachedVerifyMulti is also public and returns the identity directly,
	// without VerifyMulti's wrapper clearing it on error. Pin the same
	// no-identity-on-total-failure contract at this layer so that a regression
	// returning the last candidate alongside the error cannot hide behind the
	// higher-level wrapper.
	t.Run("DetachedVerifyMulti returns no identity on total failure", func(t *testing.T) {
		for name, key := range map[string]interface{}{
			"wrong key for every signature": &otherKey.PublicKey,
			"no matching kid anywhere": &JSONWebKeySet{Keys: []JSONWebKey{
				{KeyID: "kid-unknown", Key: &signingKey.PublicKey},
			}},
		} {
			idx, sig, err := parsed.DetachedVerifyMulti(payload, key)
			if !errors.Is(err, ErrCryptoFailure) {
				t.Fatalf("%s: expected ErrCryptoFailure, got %v", name, err)
			}
			if idx != -1 {
				t.Fatalf("%s: failure index = %d, want -1", name, idx)
			}
			if sig.Header.KeyID != "" || sig.Signature != nil ||
				sig.Header.Algorithm != "" || sig.Protected.Algorithm != "" || sig.Unprotected.Algorithm != "" {
				t.Fatalf("%s: no signature identity may be returned on total failure", name)
			}
		}
	})
}

// TestTrustIsolationParseTimeIllegalKeyIsMessageWide pins the contract split:
// an illegal key in any signature's header is a parse-time, message-wide error.
// It must never be downgraded to a signature that VerifyMulti may skip, even
// when another signature in the same message is genuine.
func TestTrustIsolationParseTimeIllegalKeyIsMessageWide(t *testing.T) {
	payload := []byte("parse-time rejection payload")
	goodKey := trustIsolationECKey(t)

	good := trustIsolationRawSignature(t, trustIsolationSign(t, ES256, goodKey, "kid-good", nil, payload))

	alg := json.RawMessage(`"ES256"`)
	privateJWK := json.RawMessage(trustIsolationJWKBytes(t, goodKey, ""))
	badHeader := rawHeader{headerAlgorithm: &alg, headerJWK: &privateJWK}
	bad := rawSignatureInfo{
		Protected: newBuffer(trustIsolationBytes(t, badHeader)),
		Signature: newBuffer([]byte("irrelevant")),
	}

	for name, sigs := range map[string][]rawSignatureInfo{
		"illegal first":  {bad, good},
		"illegal second": {good, bad},
	} {
		t.Run(name, func(t *testing.T) {
			msg := string(trustIsolationBytes(t, rawJSONWebSignature{
				Payload:    newBuffer(payload),
				Signatures: sigs,
			}))
			obj, err := ParseSigned(msg, []SignatureAlgorithm{ES256})
			if err == nil {
				t.Fatal("illegal embedded key must reject the whole message at parse time")
			}
			if !strings.Contains(err.Error(), "private parameters") {
				t.Fatalf("expected private-parameter rejection, got %v", err)
			}
			if obj != nil {
				t.Fatal("rejected message must not yield a parsed object")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Area 3: trusted JWKS selection with duplicate "kid" values
// ---------------------------------------------------------------------------

// TestTrustIsolationJWKSDuplicateKidSelection documents how selection order
// shapes single- and multi-signature results when two distinct keys share a
// "kid": the first matching JWK is the only candidate tried, and an identity is
// returned only for the signature that verified under it.
func TestTrustIsolationJWKSDuplicateKidSelection(t *testing.T) {
	payload := []byte("duplicate kid selection payload")
	const sharedKid = "shared-kid"

	keyA := trustIsolationECKey(t)
	keyB := trustIsolationECKey(t)
	keyC := trustIsolationECKey(t)

	jwksAB := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: sharedKid, Key: &keyA.PublicKey},
		{KeyID: sharedKid, Key: &keyB.PublicKey},
	}}
	jwksBA := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: sharedKid, Key: &keyB.PublicKey},
		{KeyID: sharedKid, Key: &keyA.PublicKey},
	}}

	t.Run("single signature follows the first listed key", func(t *testing.T) {
		signed := trustIsolationSign(t, ES256, keyB, sharedKid, nil, payload)
		parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}

		// keyA is first under the shared kid and cannot verify keyB's
		// signature; later duplicates are not tried.
		if _, err := parsed.Verify(jwksAB); !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure for wrong first duplicate, got %v", err)
		}

		// Reordering the set puts the matching key first, and it verifies.
		out, err := parsed.Verify(jwksBA)
		if err != nil {
			t.Fatalf("matching key first must verify: %v", err)
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}
	})

	t.Run("multi signature returns the index that verified", func(t *testing.T) {
		first := trustIsolationSign(t, ES256, keyA, sharedKid, nil, payload)
		second := trustIsolationSign(t, ES256, keyB, sharedKid, nil, payload)
		parsed, err := ParseSigned(trustIsolationGeneral(t, payload, first, second), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}

		// Set order A,B selects keyA for every signature; only index 0 (signed
		// by keyA) can pass.
		idx, sig, out, err := parsed.VerifyMulti(jwksAB)
		if err != nil {
			t.Fatalf("keyA-first must verify index 0: %v", err)
		}
		if idx != 0 || sig.Header.KeyID != sharedKid {
			t.Fatalf("got index %d kid %q, want index 0 kid %q", idx, sig.Header.KeyID, sharedKid)
		}
		if !bytes.Equal(sig.Signature, parsed.Signatures[idx].Signature) {
			t.Fatal("returned signature does not belong to the verified entry")
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}

		// Flipping set order changes the selected key, so index 1 passes. This
		// proves the returned identity follows the key that verified, not a
		// fixed position.
		idx, sig, _, err = parsed.VerifyMulti(jwksBA)
		if err != nil {
			t.Fatalf("keyB-first must verify index 1: %v", err)
		}
		if idx != 1 || sig.Header.KeyID != sharedKid {
			t.Fatalf("got index %d kid %q, want index 1 kid %q", idx, sig.Header.KeyID, sharedKid)
		}
	})

	t.Run("only the first duplicate is ever a candidate", func(t *testing.T) {
		first := trustIsolationSign(t, ES256, keyA, sharedKid, nil, payload)
		second := trustIsolationSign(t, ES256, keyB, sharedKid, nil, payload)
		parsed, err := ParseSigned(trustIsolationGeneral(t, payload, first, second), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}

		// keyC is listed first under the shared kid; keyB is present later but
		// is never tried, so nothing authenticates even though keyB signed a
		// signature in the message.
		jwksCB := &JSONWebKeySet{Keys: []JSONWebKey{
			{KeyID: sharedKid, Key: &keyC.PublicKey},
			{KeyID: sharedKid, Key: &keyB.PublicKey},
		}}
		idx, sig, out, err := parsed.VerifyMulti(jwksCB)
		if err == nil {
			t.Fatal("expected failure: a later duplicate kid must not rescue verification")
		}
		if !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure, got %v", err)
		}
		if idx != -1 || out != nil || sig.Signature != nil {
			t.Fatalf("got index %d payload %v on total failure", idx, out)
		}
	})

	t.Run("tryJWKS returns the first key for a duplicated kid", func(t *testing.T) {
		selected, err := tryJWKS(jwksAB, Header{KeyID: sharedKid})
		if err != nil {
			t.Fatal(err)
		}
		gotEC, ok := selected.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("selected key type %T, want *ecdsa.PublicKey", selected)
		}
		if !gotEC.Equal(&keyA.PublicKey) {
			t.Fatal("tryJWKS did not return the first JWK for a duplicated kid")
		}
		if _, err := tryJWKS(jwksAB, Header{KeyID: "missing"}); !errors.Is(err, ErrJWKSKidNotFound) {
			t.Fatalf("missing kid must return ErrJWKSKidNotFound, got %v", err)
		}
	})
}

// TestTrustIsolationJWKSSharedKidDifferentTypes documents that reusing a "kid"
// across key types does not make the identity interchangeable: selection order
// plus the key-type constraint decide the result, and the returned identity
// always belongs to the signature that verified.
func TestTrustIsolationJWKSSharedKidDifferentTypes(t *testing.T) {
	payload := []byte("mixed key types under one kid")
	const sharedKid = "alg-shared-kid"

	ecKey := trustIsolationECKey(t)

	jwksECFirst := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: sharedKid, Key: &ecKey.PublicKey},
		{KeyID: sharedKid, Key: &rsaTestKey.PublicKey},
	}}
	jwksRSAFirst := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: sharedKid, Key: &rsaTestKey.PublicKey},
		{KeyID: sharedKid, Key: &ecKey.PublicKey},
	}}

	t.Run("single RSA signature depends on which key is first", func(t *testing.T) {
		parsed, err := ParseSigned(trustIsolationSign(t, RS256, rsaTestKey, sharedKid, nil, payload).FullSerialize(), []SignatureAlgorithm{RS256})
		if err != nil {
			t.Fatal(err)
		}

		// The EC key is selected first and cannot perform RS256. There is no
		// fallback to the RSA entry with the same kid.
		if _, err := parsed.Verify(jwksECFirst); !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure with wrong-type key first, got %v", err)
		}
		if _, err := parsed.Verify(jwksRSAFirst); err != nil {
			t.Fatalf("RSA-first selection must verify: %v", err)
		}
	})

	t.Run("multi signature identity follows the key that verified", func(t *testing.T) {
		rsaSigned := trustIsolationSign(t, RS256, rsaTestKey, sharedKid, nil, payload)
		ecSigned := trustIsolationSign(t, ES256, ecKey, sharedKid, nil, payload)
		parsed, err := ParseSigned(trustIsolationGeneral(t, payload, rsaSigned, ecSigned), []SignatureAlgorithm{RS256, ES256})
		if err != nil {
			t.Fatal(err)
		}

		// EC first: index 0 (RS256) cannot use the EC key and is skipped; index
		// 1 (ES256) verifies. The returned alg proves which signature passed.
		idx, sig, out, err := parsed.VerifyMulti(jwksECFirst)
		if err != nil {
			t.Fatalf("ES256 signature must still verify: %v", err)
		}
		if idx != 1 || sig.Header.Algorithm != string(ES256) {
			t.Fatalf("got index %d alg %q, want index 1 alg %q", idx, sig.Header.Algorithm, ES256)
		}
		if !bytes.Equal(sig.Signature, parsed.Signatures[idx].Signature) {
			t.Fatal("returned signature does not belong to the verified entry")
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}

		// RSA first: index 0 now verifies under the selected RSA key.
		idx, sig, _, err = parsed.VerifyMulti(jwksRSAFirst)
		if err != nil {
			t.Fatalf("RSA signature must verify with RSA-first ordering: %v", err)
		}
		if idx != 0 || sig.Header.Algorithm != string(RS256) {
			t.Fatalf("got index %d alg %q, want index 0 alg %q", idx, sig.Header.Algorithm, RS256)
		}
	})

	t.Run("a private JWKS entry cannot authenticate", func(t *testing.T) {
		signed := trustIsolationSign(t, ES256, ecKey, sharedKid, nil, payload)
		parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}

		// A caller-supplied set may contain a private key by mistake; it must
		// not be treated as a verification key.
		jwksPrivateFirst := &JSONWebKeySet{Keys: []JSONWebKey{
			{KeyID: sharedKid, Key: ecKey},
			{KeyID: sharedKid, Key: &ecKey.PublicKey},
		}}
		if _, err := parsed.Verify(jwksPrivateFirst); !errors.Is(err, ErrUnsupportedKeyType) {
			t.Fatalf("expected ErrUnsupportedKeyType for a private JWKS entry, got %v", err)
		}
		idx, _, out, err := parsed.VerifyMulti(jwksPrivateFirst)
		if !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("multi: expected ErrCryptoFailure, got %v", err)
		}
		if idx != -1 || out != nil {
			t.Fatalf("multi: got index %d payload %v on failure", idx, out)
		}

		// The public entry with the same kid verifies when selected first.
		jwksPublicFirst := &JSONWebKeySet{Keys: []JSONWebKey{
			{KeyID: sharedKid, Key: &ecKey.PublicKey},
			{KeyID: sharedKid, Key: ecKey},
		}}
		if _, err := parsed.Verify(jwksPublicFirst); err != nil {
			t.Fatalf("public-first selection must verify: %v", err)
		}
	})

	t.Run("JWK alg and use metadata do not substitute for key material", func(t *testing.T) {
		signed := trustIsolationSign(t, ES256, ecKey, sharedKid, nil, payload)
		parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}

		// The caller's set entry claims a different alg and "use":"enc". Those
		// fields are advisory; the trust decision is made from the key material
		// and the actual signature, never from the kid alone.
		jwksMislabeled := &JSONWebKeySet{Keys: []JSONWebKey{{
			KeyID:     sharedKid,
			Algorithm: string(RS256),
			Use:       "enc",
			Key:       &ecKey.PublicKey,
		}}}
		if _, err := parsed.Verify(jwksMislabeled); err != nil {
			t.Fatalf("key material, not JWK metadata, decides verification: %v", err)
		}

		// The same kid with different material must not authenticate the
		// signature just because the label matches.
		otherKey := trustIsolationECKey(t)
		jwksWrongMaterial := &JSONWebKeySet{Keys: []JSONWebKey{{
			KeyID:     sharedKid,
			Algorithm: string(ES256),
			Key:       &otherKey.PublicKey,
		}}}
		if _, err := parsed.Verify(jwksWrongMaterial); !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("matching kid with different key material must not verify, got %v", err)
		}
	})
}

// TestTrustIsolationJWKSMissingKidAndEmptySet covers the selection contract for
// the absence of a usable candidate: a signature without "kid" cannot be
// selected from a JWKS, and an empty set yields no candidate at all.
func TestTrustIsolationJWKSMissingKidAndEmptySet(t *testing.T) {
	payload := []byte("kid selection contract")
	key := trustIsolationECKey(t)

	// A raw key signer emits no kid header.
	parsed, err := ParseSigned(trustIsolationSign(t, ES256, key, "", nil, payload).FullSerialize(), []SignatureAlgorithm{ES256})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Signatures[0].Header.KeyID != "" {
		t.Fatal("test setup expects a signature without a kid")
	}

	jwks := &JSONWebKeySet{Keys: []JSONWebKey{{KeyID: "some-kid", Key: &key.PublicKey}}}

	t.Run("single Verify reports key-selection failure", func(t *testing.T) {
		if _, err := parsed.Verify(jwks); !errors.Is(err, ErrJWKSKidNotFound) {
			t.Fatalf("expected ErrJWKSKidNotFound, got %v", err)
		}
	})

	t.Run("multi Verify skips and fails without a trusted payload", func(t *testing.T) {
		idx, sig, out, err := parsed.VerifyMulti(jwks)
		if !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure, got %v", err)
		}
		if idx != -1 || out != nil || sig.Signature != nil {
			t.Fatalf("got index %d payload %v on failure", idx, out)
		}
	})

	t.Run("empty JWKS has no candidate", func(t *testing.T) {
		if _, err := parsed.Verify(&JSONWebKeySet{}); !errors.Is(err, ErrJWKSKidNotFound) {
			t.Fatalf("expected ErrJWKSKidNotFound, got %v", err)
		}
		idx, _, out, err := parsed.VerifyMulti(&JSONWebKeySet{})
		if !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure, got %v", err)
		}
		if idx != -1 || out != nil {
			t.Fatalf("got index %d payload %v on failure", idx, out)
		}
	})

	t.Run("a directly supplied key needs no kid", func(t *testing.T) {
		out, err := parsed.Verify(&key.PublicKey)
		if err != nil {
			t.Fatalf("direct key verification must not require a kid: %v", err)
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}
	})
}
