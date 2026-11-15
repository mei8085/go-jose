/*-
 * Copyright 2024 Square Inc.
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
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/go-jose/go-jose/v4/json"
)

// These tests cover the RFC 7516 requirement that the three JWE header layers
// (protected, shared unprotected and per-recipient) must not carry conflicting
// values for the same parameter. In particular, an unauthenticated unprotected
// or per-recipient header copy must never be able to shadow the authenticated
// protected header's "alg", "enc", "kid" or "nonce".
//
// Both JWE Compact Serialization and JWE JSON Serialization (flattened and
// general, single- and multi-recipient) are exercised, with several local
// symmetric and asymmetric keys.

// headerConflictParamNames is the human-readable list used in sub-test names.
var headerConflictParamNames = []string{"alg", "enc", "kid", "nonce"}

// conflictTestKeyAlgorithms lists every key-management algorithm that the
// crafted messages may claim. Because conflicts must be rejected while parsing
// and before any algorithm allow-list decision, all claimed values are passed
// as allowed so that a rejection can only come from the conflict check itself.
var conflictTestKeyAlgorithms = []KeyAlgorithm{
	DIRECT, A128KW, A256KW, A128GCMKW, A256GCMKW,
	RSA_OAEP, RSA_OAEP_256, ECDH_ES, ECDH_ES_A128KW,
	KeyAlgorithm("A192KW"), KeyAlgorithm("RSA1_5"),
}

// conflictTestContentEncryption lists every content-encryption algorithm the
// crafted messages may claim, for the same reason as above.
var conflictTestContentEncryption = []ContentEncryption{
	A128GCM, A192GCM, A256GCM, A128CBC_HS256, A256CBC_HS512,
}

// b64url is a compact RawURLEncoding helper for building crafted JWEs.
func b64url(in []byte) string {
	return base64.RawURLEncoding.EncodeToString(in)
}

// mustMarshalHeader serializes a rawHeader to JSON.
func mustMarshalHeader(t *testing.T, h rawHeader) []byte {
	t.Helper()
	out, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshaling header: %v", err)
	}
	return out
}

// setHeaderString sets a string-valued header parameter.
func setHeaderString(t *testing.T, h rawHeader, key HeaderKey, value interface{}) {
	t.Helper()
	if err := h.set(key, value); err != nil {
		t.Fatalf("setting header %q=%v: %v", key, value, err)
	}
}

// cloneRawHeader returns a shallow copy of a rawHeader.
func cloneRawHeader(h rawHeader) rawHeader {
	out := rawHeader{}
	for k, v := range h {
		out[k] = v
	}
	return out
}

// jsonConflictJWE assembles a general JWE JSON Serialization message from raw
// header maps. Any layer may be nil. The iv/ciphertext/tag placeholders keep
// the message parseable; conflict rejection happens before decryption.
func jsonConflictJWE(t *testing.T, protected, unprotected rawHeader, recipients []rawHeader, flattened bool) string {
	t.Helper()

	msg := map[string]interface{}{
		"iv":         b64url(make([]byte, 12)),
		"ciphertext": b64url([]byte{0x01}),
		"tag":        b64url(make([]byte, 16)),
	}

	// headerAsMap converts a rawHeader into a generic map so it can be embedded
	// as a nested JSON object (the fork's json package does not round-trip
	// json.RawMessage through map[string]interface{}).
	headerAsMap := func(h rawHeader) map[string]interface{} {
		out := map[string]interface{}{}
		for k, v := range h {
			var decoded interface{}
			if err := json.Unmarshal(*v, &decoded); err != nil {
				t.Fatalf("decoding header value %q: %v", k, err)
			}
			out[string(k)] = decoded
		}
		return out
	}

	if protected != nil {
		msg["protected"] = b64url(mustMarshalHeader(t, protected))
	}
	if unprotected != nil {
		// The shared unprotected header is a raw JSON object (only the
		// protected header is base64url-encoded).
		msg["unprotected"] = headerAsMap(unprotected)
	}

	if flattened {
		// Flattened serialization: at most one recipient, using the top-level
		// "header" and "encrypted_key". No recipient means the fields are
		// omitted entirely.
		if len(recipients) > 1 {
			t.Fatalf("flattened JWE cannot have %d recipients", len(recipients))
		}
		if len(recipients) == 1 {
			msg["header"] = headerAsMap(recipients[0])
			msg["encrypted_key"] = b64url([]byte{0x02})
		}
	} else if len(recipients) > 0 {
		rawRecipients := make([]map[string]interface{}, 0, len(recipients))
		for i, h := range recipients {
			rawRecipients = append(rawRecipients, map[string]interface{}{
				"header":        headerAsMap(h),
				"encrypted_key": b64url([]byte{byte(i + 2)}),
			})
		}
		msg["recipients"] = rawRecipients
	}

	out, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshaling crafted JWE: %v", err)
	}
	return string(out)
}

// expectParseConflict parses input with the JSON and generic entry points and
// asserts that parsing is refused. For nonce parameters the library also
// enforces an independent blanket ban on nonce outside the protected header
// (ErrUnprotectedNonce), so either that sentinel or ErrHeaderConflict is an
// acceptable stable rejection.
func expectParseConflict(t *testing.T, input, where string, expectCompact bool) {
	t.Helper()

	acceptable := func(err error) bool {
		return errors.Is(err, ErrHeaderConflict) || errors.Is(err, ErrUnprotectedNonce)
	}

	if expectCompact {
		_, err := ParseEncryptedCompact(input, conflictTestKeyAlgorithms, conflictTestContentEncryption)
		if !acceptable(err) {
			t.Errorf("%s: compact parse error = %v, want ErrHeaderConflict", where, err)
		}
	}

	_, err := ParseEncryptedJSON(input, conflictTestKeyAlgorithms, conflictTestContentEncryption)
	if !acceptable(err) {
		t.Errorf("%s: JSON parse error = %v, want ErrHeaderConflict", where, err)
	}

	// The generic parser must reject it as well, regardless of the leading
	// character heuristic.
	_, err = ParseEncrypted(input, conflictTestKeyAlgorithms, conflictTestContentEncryption)
	if !acceptable(err) {
		t.Errorf("%s: generic parse error = %v, want ErrHeaderConflict", where, err)
	}
}

// TestJWEHeaderConflict_ProtectedVsUnprotected_JSON covers every parameter
// (alg, enc, kid, nonce) appearing with a different value in the protected
// header and the shared unprotected header, in both flattened and general JSON
// serialization. All combinations must be rejected at parse time.
func TestJWEHeaderConflict_ProtectedVsUnprotected_JSON(t *testing.T) {
	values := map[string][2]string{
		"alg":   {"A128KW", "A256KW"},
		"enc":   {"A128GCM", "A256GCM"},
		"kid":   {"key-one", "key-two"},
		"nonce": {"nonce-one", "nonce-two"},
	}
	keys := map[string]HeaderKey{
		"alg":   headerAlgorithm,
		"enc":   headerEncryption,
		"kid":   headerKeyID,
		"nonce": headerNonce,
	}

	for _, param := range headerConflictParamNames {
		param := param
		t.Run(param, func(t *testing.T) {
			for _, flattened := range []bool{false, true} {
				flattened := flattened
				form := "general"
				if flattened {
					form = "flattened"
				}
				t.Run(form, func(t *testing.T) {
					protected := rawHeader{}
					unprotected := rawHeader{}
					// Keep alg/enc present in the protected header so the
					// message is otherwise complete.
					setHeaderString(t, protected, headerAlgorithm, DIRECT)
					setHeaderString(t, protected, headerEncryption, A128GCM)
					setHeaderString(t, protected, keys[param], values[param][0])
					setHeaderString(t, unprotected, keys[param], values[param][1])

					// A recipient header is optional for the flattened form;
					// include an empty one so the message shape stays uniform.
					var recipients []rawHeader
					if flattened {
						recipients = []rawHeader{{}}
					}
					input := jsonConflictJWE(t, protected, unprotected, recipients, flattened)
					expectParseConflict(t, input, fmt.Sprintf("protected vs unprotected %q", param), false)
				})
			}
		})
	}
}

// TestJWEHeaderConflict_ProtectedVsRecipient_JSON covers every parameter
// conflicting between the protected header and a per-recipient header, in
// flattened and general JSON, including a genuine multi-recipient message
// where only one recipient carries the conflicting value.
func TestJWEHeaderConflict_ProtectedVsRecipient_JSON(t *testing.T) {
	values := map[string][2]string{
		"alg":   {"RSA-OAEP", "RSA-OAEP-256"},
		"enc":   {"A128GCM", "A192GCM"},
		"kid":   {"recipient-one", "recipient-two"},
		"nonce": {"nonce-a", "nonce-b"},
	}
	keys := map[string]HeaderKey{
		"alg":   headerAlgorithm,
		"enc":   headerEncryption,
		"kid":   headerKeyID,
		"nonce": headerNonce,
	}

	for _, param := range headerConflictParamNames {
		param := param
		t.Run(param, func(t *testing.T) {
			// Flattened (one recipient), general (one recipient), general
			// multi-recipient (two recipients, second one conflicting).
			cases := []struct {
				name       string
				flattened  bool
				recipients []rawHeader
			}{
				{
					name:       "flattened-single-recipient",
					flattened:  true,
					recipients: []rawHeader{rawStringHeader(t, keys[param], values[param][1])},
				},
				{
					name:       "general-single-recipient",
					flattened:  false,
					recipients: []rawHeader{rawStringHeader(t, keys[param], values[param][1])},
				},
				{
					name:      "general-multi-recipient-second-conflicts",
					flattened: false,
					recipients: []rawHeader{
						// First recipient carries no conflicting copy.
						rawStringHeader(t, headerAlgorithm, "RSA-OAEP"),
						// Second recipient carries the conflicting value.
						func() rawHeader {
							h := rawStringHeader(t, headerAlgorithm, "RSA-OAEP")
							setHeaderString(t, h, keys[param], values[param][1])
							return h
						}(),
					},
				},
			}

			for _, tc := range cases {
				tc := tc
				t.Run(tc.name, func(t *testing.T) {
					protected := rawHeader{}
					setHeaderString(t, protected, headerAlgorithm, RSA_OAEP)
					setHeaderString(t, protected, headerEncryption, A128GCM)
					setHeaderString(t, protected, keys[param], values[param][0])

					input := jsonConflictJWE(t, protected, nil, tc.recipients, tc.flattened)
					expectParseConflict(t, input, fmt.Sprintf("protected vs recipient %q", param), false)
				})
			}
		})
	}
}

// TestJWEHeaderConflict_UnprotectedVsRecipient_JSON covers every parameter
// conflicting between the shared unprotected header and a per-recipient header
// while the protected header stays silent on that parameter. The unauthenticated
// shared header must not be allowed to disagree with the recipient layer either.
func TestJWEHeaderConflict_UnprotectedVsRecipient_JSON(t *testing.T) {
	values := map[string][2]string{
		"alg":   {"A128GCMKW", "A256GCMKW"},
		"enc":   {"A128CBC-HS256", "A256CBC-HS512"},
		"kid":   {"shared-kid", "recipient-kid"},
		"nonce": {"shared-nonce", "recipient-nonce"},
	}
	keys := map[string]HeaderKey{
		"alg":   headerAlgorithm,
		"enc":   headerEncryption,
		"kid":   headerKeyID,
		"nonce": headerNonce,
	}

	for _, param := range headerConflictParamNames {
		param := param
		t.Run(param, func(t *testing.T) {
			for _, flattened := range []bool{false, true} {
				flattened := flattened
				form := "general"
				if flattened {
					form = "flattened"
				}
				t.Run(form, func(t *testing.T) {
					// Protected header carries alg/enc only, never the
					// conflicting parameter.
					protected := rawHeader{}
					setHeaderString(t, protected, headerAlgorithm, A128GCMKW)
					setHeaderString(t, protected, headerEncryption, A128GCM)

					unprotected := rawHeader{}
					setHeaderString(t, unprotected, keys[param], values[param][0])

					recipient := rawHeader{}
					setHeaderString(t, recipient, keys[param], values[param][1])

					input := jsonConflictJWE(t, protected, unprotected, []rawHeader{recipient}, flattened)
					expectParseConflict(t, input, fmt.Sprintf("unprotected vs recipient %q", param), false)
				})
			}
		})
	}
}

// TestJWEHeaderConflict_AllThreeLayers_JSON is the core requirement: all three
// header layers are present at once and carry different values for the same
// parameter. The message must be rejected, and the unprotected copy must never
// be able to replace the authenticated protected decision.
func TestJWEHeaderConflict_AllThreeLayers_JSON(t *testing.T) {
	values := map[string][3]string{
		"alg":   {"A128KW", "A256KW", "RSA-OAEP"},
		"enc":   {"A128GCM", "A192GCM", "A256GCM"},
		"kid":   {"layer-protected", "layer-unprotected", "layer-recipient"},
		"nonce": {"nonce-protected", "nonce-unprotected", "nonce-recipient"},
	}
	keys := map[string]HeaderKey{
		"alg":   headerAlgorithm,
		"enc":   headerEncryption,
		"kid":   headerKeyID,
		"nonce": headerNonce,
	}

	for _, param := range headerConflictParamNames {
		param := param
		t.Run(param, func(t *testing.T) {
			for _, flattened := range []bool{false, true} {
				flattened := flattened
				form := "general"
				if flattened {
					form = "flattened"
				}
				t.Run(form, func(t *testing.T) {
					protected := rawHeader{}
					unprotected := rawHeader{}
					recipient := rawHeader{}

					// Base authenticated parameters.
					setHeaderString(t, protected, headerAlgorithm, A128KW)
					setHeaderString(t, protected, headerEncryption, A128GCM)

					// The conflicting parameter appears, differently, in all
					// three layers.
					setHeaderString(t, protected, keys[param], values[param][0])
					setHeaderString(t, unprotected, keys[param], values[param][1])
					setHeaderString(t, recipient, keys[param], values[param][2])

					input := jsonConflictJWE(t, protected, unprotected, []rawHeader{recipient}, flattened)
					expectParseConflict(t, input, fmt.Sprintf("three-layer %q", param), false)
				})
			}
		})
	}
}

// TestJWEHeaderConflict_Compact exercises compact serialization. A compact JWE
// only has a protected header, so cross-layer conflicts cannot be expressed in
// this form; instead we assert that (1) a compact message whose protected
// header carries the required parameters parses and decrypts, and (2) once the
// same material is represented in JSON, adding an unprotected or recipient
// header that contradicts the protected header is rejected. This proves the
// compact form is never a route around the conflict check.
func TestJWEHeaderConflict_Compact(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes, A128GCM direct key

	encrypter, err := NewEncrypter(A128GCM, Recipient{Algorithm: DIRECT, Key: key}, nil)
	if err != nil {
		t.Fatalf("creating encrypter: %v", err)
	}
	plaintext := []byte("compact-conflict-baseline")
	obj, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("compact serializing: %v", err)
	}

	parsed, err := ParseEncryptedCompact(compact, []KeyAlgorithm{DIRECT}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatalf("parsing baseline compact JWE: %v", err)
	}
	got, err := parsed.Decrypt(key)
	if err != nil {
		t.Fatalf("decrypting baseline compact JWE: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("compact plaintext = %q, want %q", got, plaintext)
	}

	// Re-seal the same protected header / ciphertext into JSON serialization
	// and then inject contradictory unprotected and recipient header copies.
	parts := bytes.Split([]byte(compact), []byte{'.'})
	if len(parts) != 5 {
		t.Fatalf("compact JWE has %d parts, want 5", len(parts))
	}
	protectedJSON, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
	if err != nil {
		t.Fatalf("decoding protected header: %v", err)
	}
	var protected rawHeader
	if err := json.Unmarshal(protectedJSON, &protected); err != nil {
		t.Fatalf("unmarshaling protected header: %v", err)
	}

	conflicts := []struct {
		name        string
		unprotected rawHeader
		recipient   rawHeader
		kidCase     bool
	}{
		{
			name:        "unprotected-alg",
			unprotected: rawStringHeader(t, headerAlgorithm, "A256KW"),
		},
		{
			name:        "unprotected-enc",
			unprotected: rawStringHeader(t, headerEncryption, "A256GCM"),
		},
		{
			name:        "unprotected-kid",
			unprotected: rawStringHeader(t, headerKeyID, "attacker-kid"),
			kidCase:     true,
		},
		{
			name:      "recipient-alg",
			recipient: rawStringHeader(t, headerAlgorithm, "A256KW"),
		},
		{
			name:      "recipient-kid",
			recipient: rawStringHeader(t, headerKeyID, "attacker-kid"),
			kidCase:   true,
		},
	}

	for _, tc := range conflicts {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// For kid conflicts the baseline has no protected kid, so first
			// place an authenticated kid in a clone of the protected header.
			// This changes the protected bytes (invalidating the tag), but
			// rejection happens at parse time, before any decryption attempt.
			protectedClone := cloneRawHeader(protected)
			if tc.kidCase {
				setHeaderString(t, protectedClone, headerKeyID, "real-kid")
			}
			input := jsonConflictJWE(t,
				protectedClone,
				cloneRawHeader(tc.unprotected),
				[]rawHeader{cloneRawHeader(tc.recipient)},
				true, // flattened JSON
			)
			expectParseConflict(t, input, "compact-derived JSON "+tc.name, false)
		})
	}

	// A compact JWE can never carry an unprotected nonce: confirm the compact
	// parser itself has no second header layer, and an attempt to smuggle a
	// nonce via a JSON reinterpretation of the material is still rejected
	// (nonce in an unprotected layer is independently rejected as well).
	unprotected := rawStringHeader(t, headerNonce, "smuggled-nonce")
	input := jsonConflictJWE(t, cloneRawHeader(protected), unprotected, nil, true)
	if _, err := ParseEncryptedJSON(input, conflictTestKeyAlgorithms, conflictTestContentEncryption); err == nil {
		t.Errorf("expected rejection of unprotected nonce, got nil error")
	}
}

// TestJWEHeaderConflict_NonceStaysRejected verifies that the existing
// unprotected-nonce rejection and the new conflict check compose: a nonce in
// any non-protected layer is rejected, whether or not it duplicates the
// protected value.
func TestJWEHeaderConflict_NonceStaysRejected(t *testing.T) {
	protected := rawHeader{}
	setHeaderString(t, protected, headerAlgorithm, DIRECT)
	setHeaderString(t, protected, headerEncryption, A128GCM)
	setHeaderString(t, protected, headerNonce, "protected-nonce")

	cases := []struct {
		name        string
		unprotected rawHeader
		recipient   rawHeader
	}{
		{
			name:        "different-unprotected-nonce",
			unprotected: rawStringHeader(t, headerNonce, "other-nonce"),
		},
		{
			name:        "duplicate-unprotected-nonce",
			unprotected: rawStringHeader(t, headerNonce, "protected-nonce"),
		},
		{
			name:      "different-recipient-nonce",
			recipient: rawStringHeader(t, headerNonce, "other-nonce"),
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var recipients []rawHeader
			if tc.recipient != nil {
				recipients = []rawHeader{tc.recipient}
			}
			input := jsonConflictJWE(t, protected, tc.unprotected, recipients, true)
			if _, err := ParseEncryptedJSON(input, conflictTestKeyAlgorithms, conflictTestContentEncryption); err == nil {
				t.Errorf("%s: expected parse error, got nil", tc.name)
			} else if !errors.Is(err, ErrUnprotectedNonce) && !errors.Is(err, ErrHeaderConflict) {
				t.Errorf("%s: error = %v, want ErrUnprotectedNonce or ErrHeaderConflict", tc.name, err)
			}
		})
	}
}

// TestJWEHeaderConflict_IdenticalDuplicatesAllowed ensures that the same
// parameter appearing in multiple layers with byte-identical values remains
// legal (RFC 7516 only forbids disagreeing duplicates).
func TestJWEHeaderConflict_IdenticalDuplicatesAllowed(t *testing.T) {
	key := []byte("0123456789abcdef")
	// Put kid in the authenticated protected header up front, so the test can
	// add an identical unprotected copy without ever touching protected bytes
	// (and therefore without invalidating the authentication tag).
	opts := (&EncrypterOptions{}).WithHeader(headerKeyID, "same-kid")
	encrypter, err := NewEncrypter(A128GCM, Recipient{Algorithm: DIRECT, Key: key}, opts)
	if err != nil {
		t.Fatalf("creating encrypter: %v", err)
	}
	obj, err := encrypter.Encrypt([]byte("identical duplicates"))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	full := obj.FullSerialize()

	var msg map[string]*json.RawMessage
	if err := json.Unmarshal([]byte(full), &msg); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}

	// Decode the protected header to copy its exact alg/enc/kid values into
	// the unprotected header verbatim.
	var protectedB64String string
	if err := json.Unmarshal(*msg["protected"], &protectedB64String); err != nil {
		t.Fatalf("decoding protected b64: %v", err)
	}
	protectedJSON, err := base64.RawURLEncoding.DecodeString(protectedB64String)
	if err != nil {
		t.Fatalf("base64 decoding protected: %v", err)
	}
	var protected rawHeader
	if err := json.Unmarshal(protectedJSON, &protected); err != nil {
		t.Fatalf("unmarshaling protected: %v", err)
	}

	dup := rawHeader{}
	for _, param := range jweHeaderConflictParams {
		if v, ok := protected[param]; ok {
			dup[param] = v
		}
	}
	msg["unprotected"] = makeRawMessage(mustMarshalHeader(t, dup))

	raw, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("re-marshaling: %v", err)
	}

	parsed, err := ParseEncryptedJSON(string(raw), []KeyAlgorithm{DIRECT}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatalf("identical duplicates should be allowed, got: %v", err)
	}
	plaintext, err := parsed.Decrypt(key)
	if err != nil {
		t.Fatalf("decrypting with identical duplicate headers: %v", err)
	}
	if want := []byte("identical duplicates"); !bytes.Equal(plaintext, want) {
		t.Errorf("plaintext = %q, want %q", plaintext, want)
	}
}

// TestJWEAuthenticatedHeaderNotShadowed_MultiRecipient is the end-to-end
// security property for multi-recipient messages. We build a valid
// multi-recipient JWE with two local symmetric keys, then tamper with the
// unprotected and per-recipient headers to claim different alg/enc/kid values.
// Every tampered variant must be rejected at parse time, and the untampered
// message must decrypt under both keys with headers reflecting the actual
// authenticated parameters, identically across serializations.
func TestJWEAuthenticatedHeaderNotShadowed_MultiRecipient(t *testing.T) {
	keyA := []byte("keyA0123456789ab") // 16 bytes
	keyB := []byte("keyB0123456789ab") // 16 bytes
	plaintext := []byte("multi-recipient authenticated header")

	enc, err := NewMultiEncrypter(A128GCM, []Recipient{
		{Algorithm: A128GCMKW, Key: keyA, KeyID: "kid-A"},
		{Algorithm: A128GCMKW, Key: keyB, KeyID: "kid-B"},
	}, nil)
	if err != nil {
		t.Fatalf("creating multi-encrypter: %v", err)
	}
	obj, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	generalJSON := obj.FullSerialize()

	// Baseline: parse and decrypt with each local key. The selected recipient
	// index, merged header alg/enc/kid and plaintext must be correct.
	parsed, err := ParseEncryptedJSON(generalJSON,
		[]KeyAlgorithm{A128GCMKW}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatalf("parsing baseline multi-recipient JWE: %v", err)
	}

	idxA, headersA, ptA, err := parsed.DecryptMulti(keyA)
	if err != nil {
		t.Fatalf("decrypting with key A: %v", err)
	}
	if idxA != 0 {
		t.Errorf("key A selected recipient %d, want 0", idxA)
	}
	if headersA.Algorithm != string(A128GCMKW) {
		t.Errorf("key A merged alg = %q, want %q", headersA.Algorithm, A128GCMKW)
	}
	if headersA.KeyID != "kid-A" {
		t.Errorf("key A merged kid = %q, want kid-A", headersA.KeyID)
	}
	if !bytes.Equal(ptA, plaintext) {
		t.Errorf("key A plaintext = %q, want %q", ptA, plaintext)
	}

	idxB, headersB, ptB, err := parsed.DecryptMulti(keyB)
	if err != nil {
		t.Fatalf("decrypting with key B: %v", err)
	}
	if idxB != 1 {
		t.Errorf("key B selected recipient %d, want 1", idxB)
	}
	if headersB.Algorithm != string(A128GCMKW) {
		t.Errorf("key B merged alg = %q, want %q", headersB.Algorithm, A128GCMKW)
	}
	if headersB.KeyID != "kid-B" {
		t.Errorf("key B merged kid = %q, want kid-B", headersB.KeyID)
	}
	if !bytes.Equal(ptB, plaintext) {
		t.Errorf("key B plaintext = %q, want %q", ptB, plaintext)
	}

	// Now tamper: inject contradictory alg/enc/kid into the shared unprotected
	// header and into each per-recipient header. Each variant must be rejected.
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(generalJSON), &raw); err != nil {
		t.Fatalf("decoding general JWE: %v", err)
	}

	tamperCases := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{
			name: "unprotected-alg",
			mutate: func(m map[string]interface{}) {
				// No global alg exists in a multi-recipient JWE, so this alone
				// is not a conflict; pair it with an unprotected enc that
				// contradicts the protected enc below.
				m["unprotected"] = map[string]interface{}{
					"alg": "A256KW",
					"enc": "A256GCM",
				}
			},
		},
		{
			name: "unprotected-enc",
			mutate: func(m map[string]interface{}) {
				m["unprotected"] = map[string]interface{}{"enc": "A256GCM"}
			},
		},
		{
			name: "unprotected-kid",
			mutate: func(m map[string]interface{}) {
				m["unprotected"] = map[string]interface{}{"kid": "attacker-kid"}
			},
		},
		{
			name: "recipient0-enc",
			mutate: func(m map[string]interface{}) {
				// enc is global (protected), so a recipient-level copy with a
				// different value is a genuine conflict.
				rcpts := m["recipients"].([]interface{})
				r0 := rcpts[0].(map[string]interface{})
				hdr := r0["header"].(map[string]interface{})
				hdr["enc"] = "A256GCM"
			},
		},
		{
			name: "recipient1-enc",
			mutate: func(m map[string]interface{}) {
				rcpts := m["recipients"].([]interface{})
				r1 := rcpts[1].(map[string]interface{})
				hdr := r1["header"].(map[string]interface{})
				hdr["enc"] = "A192GCM"
			},
		},
		{
			name: "recipient-duplicate-kid-different-value",
			mutate: func(m map[string]interface{}) {
				// kid is already in each recipient header. Copy kid-A into the
				// global unprotected header so the unprotected layer disagrees
				// with recipient 1's authenticated kid-B.
				m["unprotected"] = map[string]interface{}{"kid": "kid-A"}
			},
		},
	}

	for _, tc := range tamperCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var tampered map[string]interface{}
			b, err := json.Marshal(raw)
			if err != nil {
				t.Fatalf("re-marshaling base: %v", err)
			}
			if err := json.Unmarshal(b, &tampered); err != nil {
				t.Fatalf("deep-copy unmarshal: %v", err)
			}
			tc.mutate(tampered)
			out, err := json.Marshal(tampered)
			if err != nil {
				t.Fatalf("marshaling tampered JWE: %v", err)
			}
			if _, err := ParseEncryptedJSON(string(out),
				[]KeyAlgorithm{A128GCMKW, A256KW, RSA_OAEP},
				[]ContentEncryption{A128GCM, A256GCM}); !errors.Is(err, ErrHeaderConflict) {
				t.Errorf("tampered %s: parse error = %v, want ErrHeaderConflict", tc.name, err)
			}
		})
	}
}

// TestJWEHeaderDecisionsConsistentAcrossSerializations verifies requirement 2:
// for a legal message, the authenticated header parameters, key-selection
// result and plaintext are identical whether the message is consumed as
// compact or JSON serialization. Uses several local keys (symmetric direct,
// symmetric key-wrap, and RSA-OAEP).
func TestJWEHeaderDecisionsConsistentAcrossSerializations(t *testing.T) {
	directKey := []byte("0123456789abcdef")   // 16 bytes -> A128GCM
	wrapKey := bytes.Repeat([]byte{0x42}, 32) // 32 bytes -> A256KW/A256GCMKW
	plaintext := []byte("same decision across serializations")

	cases := []struct {
		name      string
		enc       ContentEncryption
		recipient Recipient
		key       interface{}
		alg       KeyAlgorithm
	}{
		{
			name:      "direct-A128GCM",
			enc:       A128GCM,
			recipient: Recipient{Algorithm: DIRECT, Key: directKey, KeyID: "direct-kid"},
			key:       directKey,
			alg:       DIRECT,
		},
		{
			name:      "A256GCMKW-A128GCM",
			enc:       A128GCM,
			recipient: Recipient{Algorithm: A256GCMKW, Key: wrapKey, KeyID: "wrap-kid"},
			key:       wrapKey,
			alg:       A256GCMKW,
		},
		{
			name:      "RSA-OAEP-A128GCM",
			enc:       A128GCM,
			recipient: Recipient{Algorithm: RSA_OAEP, Key: &rsaTestKey.PublicKey, KeyID: "rsa-kid"},
			key:       rsaTestKey,
			alg:       RSA_OAEP,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			encrypter, err := NewEncrypter(tc.enc, tc.recipient, nil)
			if err != nil {
				t.Fatalf("creating encrypter: %v", err)
			}
			obj, err := encrypter.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("encrypting: %v", err)
			}

			compact, err := obj.CompactSerialize()
			if err != nil {
				t.Fatalf("compact serialize: %v", err)
			}
			flattenedJSON := obj.FullSerialize() // single recipient -> flattened form

			allowedAlgs := []KeyAlgorithm{tc.alg}
			allowedEncs := []ContentEncryption{tc.enc}

			compactObj, err := ParseEncryptedCompact(compact, allowedAlgs, allowedEncs)
			if err != nil {
				t.Fatalf("parse compact: %v", err)
			}
			jsonObj, err := ParseEncryptedJSON(flattenedJSON, allowedAlgs, allowedEncs)
			if err != nil {
				t.Fatalf("parse JSON: %v", err)
			}

			// Authenticated header decisions must match across forms.
			if compactObj.Header.Algorithm != jsonObj.Header.Algorithm {
				t.Errorf("alg: compact=%q json=%q", compactObj.Header.Algorithm, jsonObj.Header.Algorithm)
			}
			if got := compactObj.Header.Algorithm; got != string(tc.alg) {
				t.Errorf("alg = %q, want %q", got, tc.alg)
			}
			if compactObj.Header.KeyID != jsonObj.Header.KeyID {
				t.Errorf("kid: compact=%q json=%q", compactObj.Header.KeyID, jsonObj.Header.KeyID)
			}
			if compactObj.Header.KeyID != tc.recipient.KeyID {
				t.Errorf("kid = %q, want %q", compactObj.Header.KeyID, tc.recipient.KeyID)
			}
			// enc is carried in ExtraHeaders in this library; compare via the
			// merged header used for the actual cipher decision instead.
			compactEnc := compactObj.mergedHeaders(nil).getEncryption()
			jsonEnc := jsonObj.mergedHeaders(nil).getEncryption()
			if compactEnc != jsonEnc || compactEnc != tc.enc {
				t.Errorf("enc: compact=%q json=%q want=%q", compactEnc, jsonEnc, tc.enc)
			}

			// Plaintext must be identical and correct.
			ptCompact, err := compactObj.Decrypt(tc.key)
			if err != nil {
				t.Fatalf("decrypt compact: %v", err)
			}
			ptJSON, err := jsonObj.Decrypt(tc.key)
			if err != nil {
				t.Fatalf("decrypt JSON: %v", err)
			}
			if !bytes.Equal(ptCompact, ptJSON) || !bytes.Equal(ptCompact, plaintext) {
				t.Errorf("plaintext mismatch: compact=%q json=%q want=%q", ptCompact, ptJSON, plaintext)
			}
		})
	}
}

// TestJWEKeySelectionNotSwayedByUnprotectedKid verifies requirement 2's key
// selection aspect with a local JWKS containing multiple keys. The protected
// header's authenticated kid determines which key is used; an unprotected kid
// that disagrees is rejected rather than redirecting selection.
func TestJWEKeySelectionNotSwayedByUnprotectedKid(t *testing.T) {
	keyOne := bytes.Repeat([]byte{0x11}, 16)
	keyTwo := bytes.Repeat([]byte{0x22}, 16)

	jwks := JSONWebKeySet{
		Keys: []JSONWebKey{
			{KeyID: "kid-one", Key: keyOne},
			{KeyID: "kid-two", Key: keyTwo},
		},
	}

	plaintext := []byte("jwks key selection")
	encrypter, err := NewEncrypter(A128GCM,
		Recipient{Algorithm: A128GCMKW, Key: keyOne, KeyID: "kid-one"}, nil)
	if err != nil {
		t.Fatalf("creating encrypter: %v", err)
	}
	obj, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	// Baseline: protected kid selects kid-one, decryption via JWKS succeeds.
	goodJSON := obj.FullSerialize()
	parsed, err := ParseEncryptedJSON(goodJSON,
		[]KeyAlgorithm{A128GCMKW}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatalf("parsing good JWE: %v", err)
	}
	if parsed.Header.KeyID != "kid-one" {
		t.Fatalf("protected kid = %q, want kid-one", parsed.Header.KeyID)
	}
	pt, err := parsed.Decrypt(jwks)
	if err != nil {
		t.Fatalf("decrypting with JWKS: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Errorf("plaintext = %q, want %q", pt, plaintext)
	}

	// Tamper: add an unprotected kid claiming kid-two. This must be rejected,
	// never silently reroute key selection to keyTwo.
	var msg map[string]*json.RawMessage
	if err := json.Unmarshal([]byte(goodJSON), &msg); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	msg["unprotected"] = makeRawMessage([]byte(`{"kid":"kid-two"}`))
	tampered, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshaling tampered: %v", err)
	}
	if _, err := ParseEncryptedJSON(string(tampered),
		[]KeyAlgorithm{A128GCMKW}, []ContentEncryption{A128GCM}); !errors.Is(err, ErrHeaderConflict) {
		t.Errorf("unprotected kid override: err = %v, want ErrHeaderConflict", err)
	}

	// Same attack via the per-recipient header in a general multi-recipient
	// style message must also be rejected.
	msg2 := map[string]*json.RawMessage{}
	if err := json.Unmarshal([]byte(goodJSON), &msg2); err != nil {
		t.Fatalf("unmarshaling (2): %v", err)
	}
	msg2["header"] = makeRawMessage([]byte(`{"kid":"kid-two"}`))
	tampered2, err := json.Marshal(msg2)
	if err != nil {
		t.Fatalf("marshaling tampered (2): %v", err)
	}
	if _, err := ParseEncryptedJSON(string(tampered2),
		[]KeyAlgorithm{A128GCMKW}, []ContentEncryption{A128GCM}); !errors.Is(err, ErrHeaderConflict) {
		t.Errorf("recipient kid override: err = %v, want ErrHeaderConflict", err)
	}
}

// rawStringHeader builds a one-field rawHeader holding a JSON string value.
func rawStringHeader(t *testing.T, key HeaderKey, value string) rawHeader {
	t.Helper()
	h := rawHeader{}
	setHeaderString(t, h, key, value)
	return h
}
