/*-
 * Copyright 2026 go-jose Authors
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

// This file holds end-to-end trust-isolation regression tests. A JWK embedded
// in an untrusted JWS header and a key supplied by the verifying caller cross
// two different trust boundaries:
//
//   - syntactic validity of a key imported from a header only means the bytes
//     parse; it never conveys authorization,
//   - a trusted key supplied by the caller is the sole source of trust used to
//     authenticate a payload.
//
// The tests chain key import, trusted-JWKS key selection and multi-signature
// verification together so that a regression in any one stage cannot hide
// behind another. All key material used here is generated locally inside the
// tests; no external fixtures are read.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4/json"
)

// replaceProtectedHeader rewrites the protected header of a compact JWS with
// attacker-controlled JSON, preserving the rest of the message.
func replaceProtectedHeader(t *testing.T, compact string, protected any) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS must have three parts, got %d", len(parts))
	}
	raw, err := json.Marshal(protected)
	if err != nil {
		t.Fatalf("marshal forged protected header: %v", err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}

// ---------------------------------------------------------------------------
// Area 1: untrusted header key import vs. caller-supplied trust
// ---------------------------------------------------------------------------

// TestUntrustedHeaderJWKNeverBecomesTrustSource proves that a public key
// embedded in a message can syntactically validate the attacker's signature
// yet cannot replace the caller's own trust decision: verification against a
// caller-supplied trusted key must follow the caller's key, not the header.
func TestUntrustedHeaderJWKNeverBecomesTrustSource(t *testing.T) {
	payload := []byte("trust boundary regression payload")

	// The attacker controls this key and embeds its matching public half in
	// the JWS header. The signature is therefore cryptographically valid
	// relative to the embedded JWK.
	attackerPublic, attackerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A second, independent key stands for the caller's trusted source.
	trustedPublic, trustedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	attackerSigner, err := NewSigner(
		SigningKey{Algorithm: EdDSA, Key: attackerPrivate},
		&SignerOptions{EmbedJWK: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := attackerSigner.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	serializations := map[string]string{
		"flattened": signed.FullSerialize(),
	}
	if compact, err := signed.CompactSerialize(); err == nil {
		serializations["compact"] = compact
	}

	for name, msg := range serializations {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseSigned(msg, []SignatureAlgorithm{EdDSA})
			if err != nil {
				t.Fatalf("a valid embedded public JWK must parse: %v", err)
			}
			embedded := parsed.Signatures[0].Header.JSONWebKey
			if embedded == nil {
				t.Fatal("expected an embedded JWK in the header")
			}
			if !embedded.IsPublic() {
				t.Fatal("embedded JWK must be a public key at this point")
			}
			if !bytes.Equal(embedded.Key.(ed25519.PublicKey), attackerPublic) {
				t.Error("embedded JWK does not match attacker key")
			}

			// The embedded key does verify the attacker's signature. That only
			// proves the message is self-consistent, not that it is trusted.
			if _, err := parsed.Verify(embedded); err != nil {
				t.Fatalf("attacker signature must verify under the embedded attacker key: %v", err)
			}

			// The caller's trusted key is the actual trust anchor. The
			// embedded JWK must not be consulted implicitly: the same message
			// must fail verification against the trusted key.
			if _, err := parsed.Verify(trustedPublic); err == nil {
				t.Fatal("message verified under a caller-supplied key the attacker does not hold")
			} else if !errors.Is(err, ErrCryptoFailure) {
				t.Fatalf("expected ErrCryptoFailure for untrusted signature, got %v", err)
			}

			// Conversely, a genuinely trusted signature verifies under the
			// caller's key even though it carries no embedded JWK of its own.
			trustedSigner, err := NewSigner(SigningKey{Algorithm: EdDSA, Key: trustedPrivate}, nil)
			if err != nil {
				t.Fatal(err)
			}
			trustedJWS, err := trustedSigner.Sign(payload)
			if err != nil {
				t.Fatal(err)
			}
			trustedMsg := trustedJWS.FullSerialize()
			if name == "compact" {
				trustedMsg, err = trustedJWS.CompactSerialize()
				if err != nil {
					t.Fatal(err)
				}
			}
			parsedTrusted, err := ParseSigned(trustedMsg, []SignatureAlgorithm{EdDSA})
			if err != nil {
				t.Fatal(err)
			}
			out, err := parsedTrusted.Verify(trustedPublic)
			if err != nil {
				t.Fatalf("caller-supplied trusted public key must verify: %v", err)
			}
			if !bytes.Equal(out, payload) {
				t.Error("verified payload does not match")
			}
		})
	}
}

// TestEmbeddedJWKSwapDoesNotRedirectTrust shows that an attacker-controlled
// JWK in the untrusted header has no effect on verification: trust stays bound
// to the caller's key regardless of what a header carries. The swapped JWK is
// placed in the unprotected header so that the protected header and its
// signature remain otherwise intact.
func TestEmbeddedJWKSwapDoesNotRedirectTrust(t *testing.T) {
	payload := []byte("embedded jwk swap payload")

	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Start from a valid EdDSA message with no embedded JWK, then inject a
	// different, syntactically valid public key through the unprotected
	// header. The signature is untouched.
	signer, err := NewSigner(SigningKey{Algorithm: EdDSA, Key: signingPrivate}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	otherJWK := &JSONWebKey{Key: otherPrivate.Public()}
	signed.Signatures[0].header = &rawHeader{
		headerJWK: makeRawMessage(mustMarshalJSON(t, otherJWK)),
	}

	parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{EdDSA})
	if err != nil {
		t.Fatalf("message with a valid public JWK in the header must parse: %v", err)
	}
	injected := parsed.Signatures[0].Header.JSONWebKey
	if injected == nil {
		t.Fatal("expected the injected JWK to be exposed in the parsed header")
	}
	if bytes.Equal(injected.Key.(ed25519.PublicKey), signingPublic) {
		t.Fatal("injected JWK unexpectedly equals the signing key")
	}

	// The untouched signature was made by signingPrivate, so only the original
	// trusted key verifies it. The injected key never becomes an implicit
	// verification key.
	if _, err := parsed.Verify(signingPublic); err != nil {
		t.Fatalf("original trusted key must verify the untouched signature: %v", err)
	}
	if _, err := parsed.Verify(injected); err == nil {
		t.Fatal("header-injected JWK unexpectedly verified a signature it did not make")
	}
}

// TestHeaderKeyImportRejectsPrivateAndInvalidMaterial covers the import
// boundary itself. Private key material and malformed public keys carried in
// an untrusted header are rejected at parse time, before verification.
func TestHeaderKeyImportRejectsPrivateAndInvalidMaterial(t *testing.T) {
	payloadB64 := base64.RawURLEncoding.EncodeToString([]byte("import boundary payload"))
	signatureB64 := base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	ecPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateECJWK, err := json.Marshal(JSONWebKey{Key: ecPrivate})
	if err != nil {
		t.Fatal(err)
	}
	privateRSARaw, err := fromRsaPrivateKey(rsaTestKey)
	if err != nil {
		t.Fatal(err)
	}
	privateRSAJWK, err := json.Marshal(privateRSARaw)
	if err != nil {
		t.Fatal(err)
	}
	symmetricJWK, err := json.Marshal(rawJSONWebKey{Kty: "oct", K: newBuffer([]byte("untrusted-shared-secret"))})
	if err != nil {
		t.Fatal(err)
	}
	// An EC point with coordinates not on the declared curve. The coordinates
	// are the right length for P-256, so rejection comes from the on-curve
	// check rather than a length check.
	offCurveX := make([]byte, curveSize(elliptic.P256()))
	offCurveY := make([]byte, curveSize(elliptic.P256()))
	offCurveX[0] = 1
	offCurveY[0] = 1
	offCurveJWK, err := json.Marshal(rawJSONWebKey{
		Kty: "EC",
		Crv: "P-256",
		X:   newBuffer(offCurveX),
		Y:   newBuffer(offCurveY),
	})
	if err != nil {
		t.Fatal(err)
	}
	// A low-order Ed25519 encoding accepted by Go's verifier if not filtered.
	lowOrder := bytes.Repeat([]byte{0x00}, ed25519.PublicKeySize)
	lowOrderJWK, err := json.Marshal(rawJSONWebKey{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   newBuffer(lowOrder),
	})
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name      string
		alg       SignatureAlgorithm
		jwk       json.RawMessage
		wantError string
	}{
		{name: "EC private key material", alg: ES256, jwk: privateECJWK, wantError: "private parameters"},
		{name: "RSA private key material", alg: RS256, jwk: privateRSAJWK, wantError: "private parameters"},
		{name: "symmetric (oct) key material", alg: HS256, jwk: symmetricJWK, wantError: "private parameters"},
		{name: "off-curve EC public key", alg: ES256, jwk: offCurveJWK, wantError: "not on declared curve"},
		{name: "low-order Ed25519 public key", alg: EdDSA, jwk: lowOrderJWK, wantError: "low-order point"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			alg := json.RawMessage(`"` + tc.alg + `"`)
			jwk := json.RawMessage(tc.jwk)
			protected := rawHeader{
				headerAlgorithm: &alg,
				headerJWK:       &jwk,
			}
			protectedB64 := newBuffer(mustMarshalJSON(t, protected)).base64()

			// All three serializations must reject the same bad import.
			messages := map[string]string{
				"compact": strings.Join([]string{protectedB64, payloadB64, signatureB64}, "."),
				"flattened": `{"payload":"` + payloadB64 +
					`","protected":"` + protectedB64 +
					`","signature":"` + signatureB64 + `"}`,
				"general": `{"payload":"` + payloadB64 +
					`","signatures":[{"protected":"` + protectedB64 +
					`","signature":"` + signatureB64 + `"}]}`,
			}

			for serialization, msg := range messages {
				t.Run(serialization, func(t *testing.T) {
					_, err := ParseSigned(msg, []SignatureAlgorithm{tc.alg})
					if err == nil {
						t.Fatalf("expected parse rejection of %s in %s", tc.name, serialization)
					}
					if !strings.Contains(err.Error(), tc.wantError) {
						t.Fatalf("error %q does not contain %q", err.Error(), tc.wantError)
					}
				})
			}
		})
	}
}

// TestAlgorithmBoundByAllowlistAndKeyType verifies that the usable algorithm
// is the intersection of the caller's parse-time allowlist and what the
// actual key type can verify, not either boundary alone.
func TestAlgorithmBoundByAllowlistAndKeyType(t *testing.T) {
	payload := []byte("algorithm constraint payload")

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey := rsaTestKey

	t.Run("parse allowlist rejects disallowed alg", func(t *testing.T) {
		signer, err := NewSigner(SigningKey{Algorithm: ES256, Key: ecKey}, nil)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := signed.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}

		// ES256 is absent from the allowlist: parsing must fail even though
		// ES256 is a perfectly valid algorithm for this EC key.
		_, err = ParseSigned(msg, []SignatureAlgorithm{RS256, EdDSA})
		var unexpected *ErrUnexpectedSignatureAlgorithm
		if !errors.As(err, &unexpected) {
			t.Fatalf("expected ErrUnexpectedSignatureAlgorithm, got %v", err)
		}
		if unexpected.Got != ES256 {
			t.Fatalf("unexpected reported algorithm %q", unexpected.Got)
		}

		// The same message parses when the allowlist includes ES256.
		parsed, err := ParseSigned(msg, []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatalf("ES256 inside the allowlist must parse: %v", err)
		}
		if _, err := parsed.Verify(&ecKey.PublicKey); err != nil {
			t.Fatalf("matching EC key must verify ES256: %v", err)
		}
	})

	t.Run("key type rejects alg the key cannot perform", func(t *testing.T) {
		signer, err := NewSigner(SigningKey{Algorithm: RS256, Key: rsaKey}, nil)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{RS256, ES256})
		if err != nil {
			t.Fatal(err)
		}

		// RS256 is allowed, but an EC key cannot perform RSA verification.
		_, err = parsed.Verify(&ecKey.PublicKey)
		if !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure when key type cannot run the alg, got %v", err)
		}
		// The correct key type succeeds.
		if _, err := parsed.Verify(&rsaKey.PublicKey); err != nil {
			t.Fatalf("RSA public key must verify RS256: %v", err)
		}
	})

	t.Run("cross-family algorithm mismatch on the same key material", func(t *testing.T) {
		// Sign with ECDSA, then relabel the protected header to RS256. The
		// allowlist admits RS256 and the EC verifier is built successfully;
		// the key-type constraint inside the verifier must still reject it.
		signer, err := NewSigner(SigningKey{Algorithm: ES256, Key: ecKey}, nil)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		compact, err := signed.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		relabeled := replaceProtectedHeader(t, compact, map[string]any{"alg": "RS256"})

		parsed, err := ParseSigned(relabeled, []SignatureAlgorithm{RS256, ES256})
		if err != nil {
			t.Fatalf("relabeled message must parse since RS256 is allowed: %v", err)
		}
		if _, err := parsed.Verify(&ecKey.PublicKey); !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure for alg/key mismatch, got %v", err)
		}
	})

	t.Run("HMAC alg constrained by the actual shared key", func(t *testing.T) {
		hs256Key := bytes.Repeat([]byte{0x11}, 32) // exactly SHA-256 output size
		signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: hs256Key}, nil)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{HS256, HS512})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parsed.Verify(hs256Key); err != nil {
			t.Fatalf("correct HMAC key must verify HS256: %v", err)
		}
		// A different shared key cannot verify the MAC: key material, not just
		// the algorithm name, is part of the trust decision.
		if _, err := parsed.Verify(bytes.Repeat([]byte{0x22}, 32)); !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure with wrong HMAC key, got %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Area 2: multi-signature contracts over a shared payload
// ---------------------------------------------------------------------------

// TestMultiSigSkippableFailureDoesNotDiscardLaterValidSignature establishes
// the distinction between skippable per-signature verification failures and
// message-wide rejection. A bad first signature is skipped while a later
// genuine signature still authenticates the payload, and the returned index
// and header belong to the signature that actually passed.
func TestMultiSigSkippableFailureDoesNotDiscardLaterValidSignature(t *testing.T) {
	payload := []byte("multi-signature shared payload")

	goodKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: ES256, Key: &JSONWebKey{KeyID: "kid-bad", Key: goodKey}},
		{Algorithm: ES256, Key: &JSONWebKey{KeyID: "kid-good", Key: goodKey}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unmatched kid is skipped, later kid verifies", func(t *testing.T) {
		// The JWKS only knows "kid-good": the first signature fails key
		// selection (a skippable failure), the second must still be reached.
		jwks := &JSONWebKeySet{Keys: []JSONWebKey{
			{KeyID: "kid-good", Key: goodKey.Public()},
		}}
		parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}
		idx, sig, out, err := parsed.VerifyMulti(jwks)
		if err != nil {
			t.Fatalf("later valid signature must not be discarded: %v", err)
		}
		if idx != 1 {
			t.Fatalf("verified index = %d, want 1", idx)
		}
		if sig.Header.KeyID != "kid-good" {
			t.Fatalf("verified kid = %q, want \"kid-good\"", sig.Header.KeyID)
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("returned payload does not match the shared payload")
		}
	})

	t.Run("corrupt first signature is skipped, later signature verifies", func(t *testing.T) {
		raw := signed.FullSerialize()
		var general rawJSONWebSignature
		if err := json.Unmarshal([]byte(raw), &general); err != nil {
			t.Fatal(err)
		}
		if len(general.Signatures) != 2 {
			t.Fatalf("expected two signatures, got %d", len(general.Signatures))
		}
		general.Signatures[0].Signature = newBuffer([]byte("not the real signature"))
		corrupt, err := json.Marshal(general)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseSigned(string(corrupt), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}
		idx, sig, _, err := parsed.VerifyMulti(goodKey.Public())
		if err != nil {
			t.Fatalf("bad signature at index 0 must not suppress index 1: %v", err)
		}
		if idx != 1 || sig.Header.KeyID != "kid-good" {
			t.Fatalf("got index %d kid %q, want index 1 kid \"kid-good\"", idx, sig.Header.KeyID)
		}
	})
}

// TestMultiSigAllFailuresReturnsNoTrustedPayload ensures that when no
// signature authenticates, the caller receives an error and no payload or
// signature identity is handed back.
func TestMultiSigAllFailuresReturnsNoTrustedPayload(t *testing.T) {
	payload := []byte("all signatures fail payload")

	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: ES256, Key: &JSONWebKey{KeyID: "kid-a", Key: signingKey}},
		{Algorithm: ES256, Key: &JSONWebKey{KeyID: "kid-b", Key: signingKey}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{ES256})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("no matching kid anywhere", func(t *testing.T) {
		jwks := &JSONWebKeySet{Keys: []JSONWebKey{
			{KeyID: "kid-unknown", Key: signingKey.Public()},
		}}
		idx, sig, out, err := parsed.VerifyMulti(jwks)
		if err == nil {
			t.Fatal("expected failure when no signature matches a trusted key")
		}
		if idx != -1 {
			t.Fatalf("failure index = %d, want -1", idx)
		}
		if out != nil {
			t.Fatal("no payload may be returned when every signature failed")
		}
		if sig.Header.KeyID != "" || sig.Signature != nil {
			t.Fatal("no signature identity may be returned on total failure")
		}
	})

	t.Run("wrong key for every signature", func(t *testing.T) {
		idx, _, out, err := parsed.VerifyMulti(otherKey.Public())
		if !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure, got %v", err)
		}
		if idx != -1 || out != nil {
			t.Fatalf("got idx %d and payload %v on total failure", idx, out)
		}
	})

	t.Run("every signature value corrupted", func(t *testing.T) {
		raw := signed.FullSerialize()
		var general rawJSONWebSignature
		if err := json.Unmarshal([]byte(raw), &general); err != nil {
			t.Fatal(err)
		}
		for i := range general.Signatures {
			general.Signatures[i].Signature = newBuffer([]byte("corrupted"))
		}
		corrupt, err := json.Marshal(general)
		if err != nil {
			t.Fatal(err)
		}
		parsedCorrupt, err := ParseSigned(string(corrupt), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}
		idx, _, out, err := parsedCorrupt.VerifyMulti(signingKey.Public())
		if !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure, got %v", err)
		}
		if idx != -1 || out != nil {
			t.Fatalf("got idx %d and payload %v on total failure", idx, out)
		}
	})
}

// TestMultiSigParseTimeIllegalKeyIsNotDowngradedToSkippable pins the
// contract difference: an illegal embedded key is a parse-time, message-wide
// error, never downgraded into a signature that VerifyMulti may merely skip,
// even when another signature in the same message is perfectly valid.
func TestMultiSigParseTimeIllegalKeyIsNotDowngradedToSkippable(t *testing.T) {
	payload := []byte("parse-time rejection payload")

	goodKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Two recipients guarantees FullSerialize uses the general
	// "signatures" array rather than flattened serialization.
	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: ES256, Key: &JSONWebKey{KeyID: "kid-good-a", Key: goodKey}},
		{Algorithm: ES256, Key: &JSONWebKey{KeyID: "kid-good-b", Key: goodKey}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	var general rawJSONWebSignature
	if err := json.Unmarshal([]byte(signed.FullSerialize()), &general); err != nil {
		t.Fatal(err)
	}
	if len(general.Signatures) != 2 {
		t.Fatalf("expected two signatures in general serialization, got %d", len(general.Signatures))
	}
	goodSignature := general.Signatures[0]

	// Build a signature whose protected header embeds private key material.
	// Its signature bytes are irrelevant: parsing must fail first.
	alg := json.RawMessage(`"ES256"`)
	badHeader := rawHeader{
		headerAlgorithm: &alg,
		headerJWK:       makeRawMessage(mustMarshalJSON(t, JSONWebKey{Key: goodKey})),
	}
	badProtected := mustMarshalJSON(t, badHeader)
	badSignature := rawSignatureInfo{
		Protected: newBuffer(badProtected),
		Signature: newBuffer([]byte("irrelevant")),
	}

	// Both orderings: the illegal signature first and the legal one first.
	for _, order := range []struct {
		name string
		sigs []rawSignatureInfo
	}{
		{name: "illegal first", sigs: []rawSignatureInfo{badSignature, goodSignature}},
		{name: "illegal second", sigs: []rawSignatureInfo{goodSignature, badSignature}},
	} {
		t.Run(order.name, func(t *testing.T) {
			msg, err := json.Marshal(rawJSONWebSignature{
				Payload:    newBuffer(payload),
				Signatures: order.sigs,
			})
			if err != nil {
				t.Fatal(err)
			}
			obj, err := ParseSigned(string(msg), []SignatureAlgorithm{ES256})
			if err == nil {
				t.Fatal("illegal embedded key in any signature must reject the whole message at parse time")
			}
			if !strings.Contains(err.Error(), "private parameters") {
				t.Fatalf("expected private parameters error, got %v", err)
			}
			if obj != nil {
				t.Fatal("no parsed object may be returned for a rejected message")
			}
		})
	}
}

// TestSingleVerifyDoesNotTreatMultiSigAsSkippable confirms the single-signature
// API refuses to downgrade a multi-signature message into "verify any one".
func TestSingleVerifyDoesNotTreatMultiSigAsSkippable(t *testing.T) {
	payload := []byte("single API multi-sig payload")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: ES256, Key: key},
		{Algorithm: ES256, Key: key},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{ES256})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Verify(key.Public()); err == nil {
		t.Fatal("Verify must reject a multi-signature message instead of silently picking one")
	} else if !strings.Contains(err.Error(), "too many signatures") {
		t.Fatalf("expected too many signatures error, got %v", err)
	}
}

// TestVerifyMultiEmptyAndNoKidContracts documents the key-selection contract
// when a signature carries no kid and verification runs against a JWKS.
func TestVerifyMultiEmptyAndNoKidContracts(t *testing.T) {
	payload := []byte("no kid contract payload")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// A signer built from a raw key without a KeyID produces no kid header.
	signer, err := NewSigner(SigningKey{Algorithm: ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{ES256})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Signatures[0].Header.KeyID != "" {
		t.Fatal("test setup expects a signature without a kid")
	}

	jwks := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: "some-kid", Key: key.Public()},
	}}

	// Multi-signature verification treats a missing kid as a skippable
	// failure; with no other candidate the whole verification fails.
	idx, _, out, err := parsed.VerifyMulti(jwks)
	if err == nil {
		t.Fatal("expected failure when a JWKS cannot be selected without a kid")
	}
	if idx != -1 || out != nil {
		t.Fatalf("got idx %d payload %v, want no result", idx, out)
	}

	// The single-signature API surfaces the key-selection error directly
	// rather than masking it as a cryptographic failure.
	_, err = parsed.Verify(jwks)
	if !errors.Is(err, ErrJWKSKidNotFound) {
		t.Fatalf("single Verify expected ErrJWKSKidNotFound, got %v", err)
	}

	// A directly supplied key needs no kid and still verifies.
	if _, err := parsed.Verify(key.Public()); err != nil {
		t.Fatalf("direct key verification must not require a kid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Area 3: trusted JWKS selection with duplicate kids / differing algorithms
// ---------------------------------------------------------------------------

// TestJWKSDuplicateKidSelectionOrder documents that a shared kid does not mean
// shared key material: tryJWKS selects the first JWK in set order, and only a
// signature that actually verifies under that selected key can authenticate.
func TestJWKSDuplicateKidSelectionOrder(t *testing.T) {
	payload := []byte("duplicate kid selection payload")

	// Two distinct keys deliberately share the same kid.
	keyFirst, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keySecond, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const sharedKid = "shared-kid"

	t.Run("single signature: first matching JWK wins and wrong first key fails", func(t *testing.T) {
		// The signature is made by keySecond, but the JWKS lists keyFirst
		// under the same kid first. Selection order means keyFirst is picked;
		// the signature cannot verify, so the message is rejected.
		signer, err := NewSigner(SigningKey{
			Algorithm: ES256,
			Key:       &JSONWebKey{KeyID: sharedKid, Key: keySecond},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}

		jwksFirstWins := &JSONWebKeySet{Keys: []JSONWebKey{
			{KeyID: sharedKid, Key: keyFirst.Public()},
			{KeyID: sharedKid, Key: keySecond.Public()},
		}}
		if _, err := parsed.Verify(jwksFirstWins); !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure when first duplicate kid cannot verify, got %v", err)
		}

		// Reversing the set order makes the matching key the first candidate,
		// and the same signed message now verifies.
		jwksSecondFirst := &JSONWebKeySet{Keys: []JSONWebKey{
			{KeyID: sharedKid, Key: keySecond.Public()},
			{KeyID: sharedKid, Key: keyFirst.Public()},
		}}
		out, err := parsed.Verify(jwksSecondFirst)
		if err != nil {
			t.Fatalf("matching key first in JWKS order must verify: %v", err)
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}
	})

	t.Run("multi signature: identity returned must belong to the verified candidate", func(t *testing.T) {
		// Two signatures over the same payload, one per distinct key, both
		// labeled with the same kid. Only the one matching the first JWKS
		// entry can authenticate; VerifyMulti must report that exact index.
		signer, err := NewMultiSigner([]SigningKey{
			{Algorithm: ES256, Key: &JSONWebKey{KeyID: sharedKid, Key: keyFirst}},
			{Algorithm: ES256, Key: &JSONWebKey{KeyID: sharedKid, Key: keySecond}},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{ES256})
		if err != nil {
			t.Fatal(err)
		}

		jwksFirstWins := &JSONWebKeySet{Keys: []JSONWebKey{
			{KeyID: sharedKid, Key: keyFirst.Public()},
			{KeyID: sharedKid, Key: keySecond.Public()},
		}}
		idx, sig, out, err := parsed.VerifyMulti(jwksFirstWins)
		if err != nil {
			t.Fatalf("first-candidate key must verify index 0: %v", err)
		}
		if idx != 0 {
			t.Fatalf("verified index = %d, want 0 (first JWKS order, first signature)", idx)
		}
		if sig.Header.KeyID != sharedKid {
			t.Fatalf("verified kid = %q, want %q", sig.Header.KeyID, sharedKid)
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}

		// Flip set order: now index 1 is the one that can pass, proving the
		// returned identity follows the selected key rather than position.
		jwksSecondFirst := &JSONWebKeySet{Keys: []JSONWebKey{
			{KeyID: sharedKid, Key: keySecond.Public()},
			{KeyID: sharedKid, Key: keyFirst.Public()},
		}}
		idx, sig, _, err = parsed.VerifyMulti(jwksSecondFirst)
		if err != nil {
			t.Fatalf("flipped order must verify index 1: %v", err)
		}
		if idx != 1 {
			t.Fatalf("verified index = %d, want 1 after JWKS order flip", idx)
		}
		if sig.Header.KeyID != sharedKid {
			t.Fatalf("verified kid = %q, want %q", sig.Header.KeyID, sharedKid)
		}
	})

	t.Run("tryJWKS unit behavior: same kid, different keys, first returned", func(t *testing.T) {
		jwks := JSONWebKeySet{Keys: []JSONWebKey{
			{KeyID: sharedKid, Key: keyFirst.Public()},
			{KeyID: sharedKid, Key: keySecond.Public()},
		}}
		selected, err := tryJWKS(&jwks, Header{KeyID: sharedKid})
		if err != nil {
			t.Fatal(err)
		}
		gotEC, ok := selected.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("selected key type %T, want *ecdsa.PublicKey", selected)
		}
		if !gotEC.Equal(&keyFirst.PublicKey) {
			t.Fatal("tryJWKS did not return the first JWK for a duplicate kid")
		}

		if _, err := tryJWKS(&jwks, Header{KeyID: "missing-kid"}); !errors.Is(err, ErrJWKSKidNotFound) {
			t.Fatalf("missing kid must return ErrJWKSKidNotFound, got %v", err)
		}
	})
}

// TestJWKSDifferentAlgorithmsSameKid shows that when a kid is reused across
// keys of different algorithm families, selection order plus the key-type
// constraint decide the outcome: an inapplicable candidate cannot authenticate
// a signature, and the verified identity always matches the key that passed.
func TestJWKSDifferentAlgorithmsSameKid(t *testing.T) {
	payload := []byte("mixed algorithm same kid payload")
	const sharedKid = "alg-shared-kid"

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey := rsaTestKey

	// One RSA and one EC JWK carrying the same kid.
	jwksECFirst := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: sharedKid, Key: ecKey.Public()},
		{KeyID: sharedKid, Key: rsaKey.Public()},
	}}
	jwksRSAFirst := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: sharedKid, Key: rsaKey.Public()},
		{KeyID: sharedKid, Key: ecKey.Public()},
	}}

	t.Run("RSA signature with EC key first in JWKS order", func(t *testing.T) {
		signer, err := NewSigner(SigningKey{
			Algorithm: RS256,
			Key:       &JSONWebKey{KeyID: sharedKid, Key: rsaKey},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{RS256})
		if err != nil {
			t.Fatal(err)
		}

		// The EC key is selected first but cannot perform RS256: the
		// single-signature API cannot skip its own only candidate.
		if _, err := parsed.Verify(jwksECFirst); !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("expected ErrCryptoFailure when first candidate is the wrong key type, got %v", err)
		}
		// With the RSA key first, selection succeeds and verification passes.
		out, err := parsed.Verify(jwksRSAFirst)
		if err != nil {
			t.Fatalf("RSA-first JWKS must verify RS256: %v", err)
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}
	})

	t.Run("multi-sig mixed algorithms: wrong-first candidate skipped, right one verifies", func(t *testing.T) {
		signer, err := NewMultiSigner([]SigningKey{
			{Algorithm: RS256, Key: &JSONWebKey{KeyID: sharedKid, Key: rsaKey}},
			{Algorithm: ES256, Key: &JSONWebKey{KeyID: sharedKid, Key: ecKey}},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{RS256, ES256})
		if err != nil {
			t.Fatal(err)
		}

		// EC key first in the JWKS. The RS256 signature at index 0 cannot
		// verify with it and is skipped; the ES256 signature at index 1
		// verifies with the same EC key. The returned identity is index 1.
		idx, sig, out, err := parsed.VerifyMulti(jwksECFirst)
		if err != nil {
			t.Fatalf("skippable wrong-type candidate must not block the valid ES256 signature: %v", err)
		}
		if idx != 1 {
			t.Fatalf("verified index = %d, want 1", idx)
		}
		if sig.Header.Algorithm != string(ES256) {
			t.Fatalf("verified alg = %q, want ES256", sig.Header.Algorithm)
		}
		if !bytes.Equal(out, payload) {
			t.Fatal("verified payload mismatch")
		}

		// RSA key first: the index-0 RS256 signature now succeeds first.
		idx, sig, _, err = parsed.VerifyMulti(jwksRSAFirst)
		if err != nil {
			t.Fatalf("RSA-first ordering must verify index 0: %v", err)
		}
		if idx != 0 || sig.Header.Algorithm != string(RS256) {
			t.Fatalf("got idx %d alg %q, want idx 0 alg RS256", idx, sig.Header.Algorithm)
		}
	})
}

// mustMarshalJSON fails the test if marshaling fails.
func mustMarshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
