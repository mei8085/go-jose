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

// This file covers detached JWS signatures and the "b64" (RFC 7797)
// header parameter.
//
// A signature must authenticate the same payload bytes no matter which
// serialization carried it. RFC 7797 section 3 defines the JWS Signing Input
// as
//
//	ASCII(BASE64URL(UTF8(protected header)) || '.') || JWS Payload      (b64=false)
//	ASCII(BASE64URL(UTF8(protected header)) || '.' ||
//	      BASE64URL(JWS Payload))                                       (b64=true)
//
// The tests below compute this input independently of the library, compare it
// with the bytes the library actually authenticates, and check that mutating
// any payload byte invalidates the signature on every verification path. They
// also check that unknown "crit" entries and inconsistent "b64" declarations
// are rejected for compact, flattened JSON and general JSON serialization.
//
// All key material and payloads are local to these tests; no external fixtures
// are read.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4/json"
)

// detachedTestKey is a locally-defined 256-bit HMAC key for HS256.
var detachedTestKey = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

// detachedBinaryPayload contains NUL, high bytes and the '.' token separator,
// so that JSON string escaping or naive dot-splitting cannot stand in for the
// authenticated payload bytes.
var detachedBinaryPayload = []byte{0x00, 0x01, 0x02, 0xfe, 0xff, '.', 0x7f, 0x80}

// detachedB64Of reports the effective "b64" value of a protected header, read
// the same way a conforming implementation must read it.
func detachedB64Of(t *testing.T, protectedJSON string) bool {
	t.Helper()
	var header rawHeader
	if err := json.Unmarshal([]byte(protectedJSON), &header); err != nil {
		t.Fatalf("invalid protected header fixture %q: %v", protectedJSON, err)
	}
	needsBase64, err := header.getB64()
	if err != nil {
		t.Fatalf("invalid b64 value in protected header fixture %q: %v", protectedJSON, err)
	}
	return needsBase64
}

// detachedExpectedAuthData computes the JWS Signing Input independently from
// the exact protected header bytes and the b64 rule the header declares.
func detachedExpectedAuthData(t *testing.T, protectedJSON string, payload []byte) []byte {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(protectedJSON)) + "."
	if detachedB64Of(t, protectedJSON) {
		input += base64.RawURLEncoding.EncodeToString(payload)
	} else {
		input += string(payload)
	}
	return []byte(input)
}

// detachedSign HS256-signs the JWS Signing Input implied by protectedJSON.
func detachedSign(t *testing.T, protectedJSON string, payload []byte) []byte {
	t.Helper()
	mac := hmac.New(sha256.New, detachedTestKey)
	_, _ = mac.Write(detachedExpectedAuthData(t, protectedJSON, payload))
	return mac.Sum(nil)
}

// detachedSignEncoded signs the b64=true signing input, whatever the protected
// header claims.
func detachedSignEncoded(t *testing.T, protectedJSON string, payload []byte) []byte {
	t.Helper()
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, detachedTestKey)
	_, _ = mac.Write([]byte(base64.RawURLEncoding.EncodeToString([]byte(protectedJSON)) + "." + encoded))
	return mac.Sum(nil)
}

// detachedSignRaw signs the b64=false signing input, whatever the protected
// header claims.
func detachedSignRaw(t *testing.T, protectedJSON string, payload []byte) []byte {
	t.Helper()
	input := append([]byte(base64.RawURLEncoding.EncodeToString([]byte(protectedJSON))+"."), payload...)
	mac := hmac.New(sha256.New, detachedTestKey)
	_, _ = mac.Write(input)
	return mac.Sum(nil)
}

// detachedAuthData returns the bytes the library authenticates for obj's only
// signature.
func detachedAuthData(t *testing.T, obj *JSONWebSignature, payload []byte) []byte {
	t.Helper()
	if len(obj.Signatures) != 1 {
		t.Fatalf("expected one signature, got %d", len(obj.Signatures))
	}
	authData, err := obj.computeAuthData(payload, &obj.Signatures[0])
	if err != nil {
		t.Fatalf("computeAuthData: %v", err)
	}
	return authData
}

// detachedSerializations holds one signature in each JWS serialization. Every
// form carries the payload base64url-encoded in the "payload" member, which is
// the representation this package uses for that member.
type detachedSerializations struct {
	compact   string
	flattened string
	general   string
}

func newDetachedSerializations(protectedJSON string, payload, signature []byte) detachedSerializations {
	protected := base64.RawURLEncoding.EncodeToString([]byte(protectedJSON))
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	return detachedSerializations{
		compact: protected + ".." + encodedSignature,
		flattened: fmt.Sprintf(
			`{"payload":"%s","protected":"%s","signature":"%s"}`,
			encodedPayload, protected, encodedSignature,
		),
		general: fmt.Sprintf(
			`{"payload":"%s","signatures":[{"protected":"%s","signature":"%s"}]}`,
			encodedPayload, protected, encodedSignature,
		),
	}
}

// newDetachedJSONWithUnprotected builds the flattened and general JSON
// serializations of a signature that carries the given JSON object in its
// unprotected header. Compact serialization cannot express an unprotected
// header, so it is left empty.
func newDetachedJSONWithUnprotected(protectedJSON, unprotectedJSON string, payload, signature []byte) detachedSerializations {
	protected := base64.RawURLEncoding.EncodeToString([]byte(protectedJSON))
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	return detachedSerializations{
		flattened: fmt.Sprintf(
			`{"payload":"%s","protected":"%s","header":%s,"signature":"%s"}`,
			encodedPayload, protected, unprotectedJSON, encodedSignature,
		),
		general: fmt.Sprintf(
			`{"payload":"%s","signatures":[{"protected":"%s","header":%s,"signature":"%s"}]}`,
			encodedPayload, protected, unprotectedJSON, encodedSignature,
		),
	}
}

// detachedParse parses every serialization. The compact form is parsed with
// ParseDetached; the JSON forms carry their payload.
func detachedParse(t *testing.T, payload []byte, serializations detachedSerializations) map[string]*JSONWebSignature {
	t.Helper()
	parsed := map[string]*JSONWebSignature{}

	obj, err := ParseDetached(serializations.compact, payload, []SignatureAlgorithm{HS256})
	if err != nil {
		t.Fatalf("ParseDetached: %v", err)
	}
	parsed["compact"] = obj

	for name, serialized := range map[string]string{
		"flattened": serializations.flattened,
		"general":   serializations.general,
	} {
		obj, err := ParseSignedJSON(serialized, []SignatureAlgorithm{HS256})
		if err != nil {
			t.Fatalf("ParseSignedJSON(%s): %v", name, err)
		}
		parsed[name] = obj
	}

	return parsed
}

// detachedParseForRejection parses serializations that are expected to be
// rejected. A message may be rejected while parsing or later while verifying;
// both satisfy the requirement. Returned are only the forms that parsed.
func detachedParseForRejection(t *testing.T, payload []byte, serializations detachedSerializations) map[string]*JSONWebSignature {
	t.Helper()
	parsed := map[string]*JSONWebSignature{}

	obj, err := ParseDetached(serializations.compact, payload, []SignatureAlgorithm{HS256})
	if err == nil {
		parsed["compact"] = obj
	}

	for name, serialized := range map[string]string{
		"flattened": serializations.flattened,
		"general":   serializations.general,
	} {
		obj, err := ParseSignedJSON(serialized, []SignatureAlgorithm{HS256})
		if err == nil {
			parsed[name] = obj
		}
	}

	return parsed
}

// detachedAssertRejected checks that every verification entry point rejects the
// given objects. Entry points that are not applicable to the object's payload
// state are skipped.
func detachedAssertRejected(t *testing.T, objects map[string]*JSONWebSignature, payload []byte) {
	t.Helper()
	for name, obj := range objects {
		if err := obj.DetachedVerify(payload, detachedTestKey); err == nil {
			t.Errorf("%s: DetachedVerify accepted the signature", name)
		}
		if _, _, err := obj.DetachedVerifyMulti(payload, detachedTestKey); err == nil {
			t.Errorf("%s: DetachedVerifyMulti accepted the signature", name)
		}
		if len(obj.payload) > 0 {
			if _, err := obj.Verify(detachedTestKey); err == nil {
				t.Errorf("%s: Verify accepted the signature", name)
			}
		}
	}
}

// detachedAssertRejectedWithHeaderError is detachedAssertRejected for messages
// whose rejection reason is a header consistency rule rather than a MAC
// mismatch. The single-signature entry points must report
// ErrUnsupportedCriticalHeader; DetachedVerifyMulti reports ErrCryptoFailure
// because it skips unusable signatures.
func detachedAssertRejectedWithHeaderError(t *testing.T, objects map[string]*JSONWebSignature, payload []byte) {
	t.Helper()
	for name, obj := range objects {
		if err := obj.DetachedVerify(payload, detachedTestKey); !errors.Is(err, ErrUnsupportedCriticalHeader) {
			t.Errorf("%s: DetachedVerify error = %v, want %v", name, err, ErrUnsupportedCriticalHeader)
		}
		if _, _, err := obj.DetachedVerifyMulti(payload, detachedTestKey); !errors.Is(err, ErrCryptoFailure) {
			t.Errorf("%s: DetachedVerifyMulti error = %v, want %v", name, err, ErrCryptoFailure)
		}
		if len(obj.payload) > 0 {
			if verified, err := obj.Verify(detachedTestKey); !errors.Is(err, ErrUnsupportedCriticalHeader) || verified != nil {
				t.Errorf("%s: Verify returned (%q, %v), want (nil, %v)", name, verified, err, ErrUnsupportedCriticalHeader)
			}
		}
	}
}

// TestDetachedAuthDataAcrossSerializations checks that the authenticated bytes
// are identical for compact, flattened JSON and general JSON serialization, and
// that they match an independent computation from the protected header and the
// b64 rule it declares.
func TestDetachedAuthDataAcrossSerializations(t *testing.T) {
	testCases := []struct {
		name          string
		protectedJSON string
	}{
		{name: "b64 absent (encoded payload)", protectedJSON: `{"alg":"HS256"}`},
		{name: "b64 true declared critical", protectedJSON: `{"alg":"HS256","b64":true,"crit":["b64"]}`},
		{name: "b64 false declared critical (unencoded payload)", protectedJSON: `{"alg":"HS256","b64":false,"crit":["b64"]}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := detachedBinaryPayload
			objects := detachedParse(t, payload, newDetachedSerializations(
				tc.protectedJSON, payload, detachedSign(t, tc.protectedJSON, payload),
			))

			expected := detachedExpectedAuthData(t, tc.protectedJSON, payload)
			if !detachedB64Of(t, tc.protectedJSON) && !bytes.HasSuffix(expected, payload) {
				t.Fatalf("unencoded signing input must end with the raw payload bytes: %q", expected)
			}

			for name, obj := range objects {
				if got := detachedAuthData(t, obj, payload); !bytes.Equal(got, expected) {
					t.Errorf("%s: authenticated bytes differ\n got: %q\nwant: %q", name, got, expected)
				}
				if err := obj.DetachedVerify(payload, detachedTestKey); err != nil {
					t.Errorf("%s: DetachedVerify rejected a valid signature: %v", name, err)
				}
				if _, _, err := obj.DetachedVerifyMulti(payload, detachedTestKey); err != nil {
					t.Errorf("%s: DetachedVerifyMulti rejected a valid signature: %v", name, err)
				}
				if verified, err := obj.Verify(detachedTestKey); err != nil {
					t.Errorf("%s: Verify rejected a valid signature: %v", name, err)
				} else if !bytes.Equal(verified, payload) {
					t.Errorf("%s: Verify returned payload %q, want %q", name, verified, payload)
				}
			}
		})
	}
}

// flattenedToGeneral converts a flattened JSON serialization to the general
// form, which is what FullSerialize emits for a single signature.
func flattenedToGeneral(t *testing.T, flattened string) string {
	t.Helper()
	var raw rawJSONWebSignature
	if err := json.Unmarshal([]byte(flattened), &raw); err != nil {
		t.Fatalf("unmarshal flattened JWS: %v", err)
	}
	if raw.Protected == nil || raw.Signature == nil {
		t.Fatal("flattened JWS has no protected header or signature")
	}
	general := rawJSONWebSignature{
		Payload: raw.Payload,
		Signatures: []rawSignatureInfo{{
			Protected: raw.Protected,
			Header:    raw.Header,
			Signature: raw.Signature,
		}},
	}
	out, err := json.Marshal(general)
	if err != nil {
		t.Fatalf("marshal general JWS: %v", err)
	}
	return string(out)
}

// TestDetachedSignerOutputAcrossSerializations signs with the library itself and
// checks that every serialization authenticates the same bytes, derived from the
// protected header segment that was actually emitted.
func TestDetachedSignerOutputAcrossSerializations(t *testing.T) {
	payload := detachedBinaryPayload

	testCases := []struct {
		name string
		opts *SignerOptions
	}{
		{name: "encoded payload", opts: nil},
		{name: "unencoded payload", opts: new(SignerOptions).WithBase64(false)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: detachedTestKey}, tc.opts)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			obj, err := signer.Sign(payload)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			if tc.opts != nil {
				// WithBase64(false) must declare b64 false and crit ["b64"].
				if obj.Signatures[0].protected == nil {
					t.Fatal("no protected header")
				}
				raw, err := json.Marshal(obj.Signatures[0].protected)
				if err != nil {
					t.Fatal(err)
				}
				if detachedB64Of(t, string(raw)) {
					t.Errorf("WithBase64(false) produced header %s", raw)
				}
				var header rawHeader
				if err := json.Unmarshal(raw, &header); err != nil {
					t.Fatal(err)
				}
				crit, err := header.getCritical()
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(strings.Join(crit, ","), headerB64) {
					t.Errorf("unencoded payload header must declare crit b64: %s", raw)
				}
			}

			compact, err := obj.CompactSerialize()
			if err != nil {
				t.Fatalf("CompactSerialize: %v", err)
			}
			detachedCompact, err := obj.DetachedCompactSerialize()
			if err != nil {
				t.Fatalf("DetachedCompactSerialize: %v", err)
			}
			full := obj.FullSerialize()
			if full == "" {
				t.Fatal("FullSerialize returned empty string")
			}
			general := flattenedToGeneral(t, full)

			// Derive the expected signing input from the protected segment
			// that was actually emitted, independently of computeAuthData.
			parts := strings.SplitN(compact, ".", 2)
			if len(parts) != 2 {
				t.Fatalf("compact serialization %q has no '.'", compact)
			}
			protectedJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				t.Fatalf("decode protected header: %v", err)
			}
			expected := detachedExpectedAuthData(t, string(protectedJSON), payload)

			type parsedForm struct {
				name string
				obj  *JSONWebSignature
			}
			forms := []parsedForm{}

			attached, err := ParseSignedCompact(compact, []SignatureAlgorithm{HS256})
			if err != nil {
				t.Fatalf("ParseSignedCompact: %v", err)
			}
			forms = append(forms, parsedForm{"compact (attached)", attached})

			detached, err := ParseDetached(detachedCompact, payload, []SignatureAlgorithm{HS256})
			if err != nil {
				t.Fatalf("ParseDetached: %v", err)
			}
			forms = append(forms, parsedForm{"compact (detached)", detached})

			for name, serialized := range map[string]string{"flattened": full, "general": general} {
				parsed, err := ParseSignedJSON(serialized, []SignatureAlgorithm{HS256})
				if err != nil {
					t.Fatalf("ParseSignedJSON(%s): %v", name, err)
				}
				forms = append(forms, parsedForm{name, parsed})
			}

			for _, form := range forms {
				if got := detachedAuthData(t, form.obj, payload); !bytes.Equal(got, expected) {
					t.Errorf("%s: authenticated bytes differ\n got: %q\nwant: %q", form.name, got, expected)
				}
				if err := form.obj.DetachedVerify(payload, detachedTestKey); err != nil {
					t.Errorf("%s: DetachedVerify: %v", form.name, err)
				}
				if _, _, err := form.obj.DetachedVerifyMulti(payload, detachedTestKey); err != nil {
					t.Errorf("%s: DetachedVerifyMulti: %v", form.name, err)
				}
				if form.name == "compact (detached)" {
					continue // carries no payload of its own
				}
				if verified, err := form.obj.Verify(detachedTestKey); err != nil {
					t.Errorf("%s: Verify: %v", form.name, err)
				} else if !bytes.Equal(verified, payload) {
					t.Errorf("%s: Verify returned %q, want %q", form.name, verified, payload)
				}
			}
		})
	}
}

// TestDetachedPayloadByteMutationsRejected checks that flipping any single byte
// of the payload invalidates the signature on every path.
func TestDetachedPayloadByteMutationsRejected(t *testing.T) {
	testCases := []struct {
		name          string
		protectedJSON string
	}{
		{name: "encoded payload", protectedJSON: `{"alg":"HS256"}`},
		{name: "unencoded payload", protectedJSON: `{"alg":"HS256","b64":false,"crit":["b64"]}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := detachedBinaryPayload
			serializations := newDetachedSerializations(
				tc.protectedJSON, payload, detachedSign(t, tc.protectedJSON, payload),
			)

			for i := range payload {
				mutated := bytes.Clone(payload)
				mutated[i] ^= 0x01

				if bytes.Equal(mutated, payload) {
					t.Fatalf("mutation at offset %d did not change the payload", i)
				}
				if bytes.Equal(
					detachedExpectedAuthData(t, tc.protectedJSON, mutated),
					detachedExpectedAuthData(t, tc.protectedJSON, payload),
				) {
					t.Fatalf("mutation at offset %d did not change the signing input", i)
				}

				objects := detachedParse(t, payload, serializations)
				for name, obj := range objects {
					if err := obj.DetachedVerify(mutated, detachedTestKey); err == nil {
						t.Errorf("%s: DetachedVerify accepted payload byte %d mutated", name, i)
					}
					if _, _, err := obj.DetachedVerifyMulti(mutated, detachedTestKey); err == nil {
						t.Errorf("%s: DetachedVerifyMulti accepted payload byte %d mutated", name, i)
					}
				}

				// Verify acts on the payload the object carries. Feeding the
				// mutated bytes through ParseDetached exercises that path with
				// the same signature.
				obj, err := ParseDetached(serializations.compact, mutated, []SignatureAlgorithm{HS256})
				if err != nil {
					t.Fatalf("ParseDetached with mutated payload: %v", err)
				}
				if _, err := obj.Verify(detachedTestKey); err == nil {
					t.Errorf("Verify accepted payload byte %d mutated", i)
				}
			}
		})
	}
}

// TestDetachedUnknownCriticalHeaderRejected checks that an unknown "crit" entry
// is rejected for every serialization and every verification entry point, and
// that "crit" is never accepted in an unprotected header.
func TestDetachedUnknownCriticalHeaderRejected(t *testing.T) {
	const protectedJSON = `{"alg":"HS256","crit":["unknown-critical-header"]}`
	payload := detachedBinaryPayload
	objects := detachedParse(t, payload, newDetachedSerializations(
		protectedJSON, payload, detachedSign(t, protectedJSON, payload),
	))

	detachedAssertRejectedWithHeaderError(t, objects, payload)

	t.Run("crit in unprotected header", func(t *testing.T) {
		serializations := newDetachedJSONWithUnprotected(
			`{"alg":"HS256"}`, `{"crit":["b64"],"b64":false}`,
			payload, detachedSignEncoded(t, `{"alg":"HS256"}`, payload),
		)
		detachedAssertRejectedWithHeaderError(t, detachedParseForRejection(t, payload, serializations), payload)
	})
}

// TestDetachedInconsistentB64DeclarationRejected covers signatures whose "b64"
// declaration does not agree with where the parameter lives or with the bytes
// that were actually signed. Each must be rejected, in every serialization.
func TestDetachedInconsistentB64DeclarationRejected(t *testing.T) {
	payload := []byte("abc")

	t.Run("crit names b64 that is only in the unprotected header", func(t *testing.T) {
		// The shape reported upstream: the protected header lists crit:["b64"]
		// but has no b64 member, while the unprotected header carries
		// b64=false. The signing input is the b64=true one, so the merged
		// header would advertise a rule the signature never followed.
		const protectedJSON = `{"alg":"HS256","crit":["b64"]}`
		serializations := newDetachedJSONWithUnprotected(
			protectedJSON, `{"b64":false}`,
			payload, detachedSignEncoded(t, protectedJSON, payload),
		)
		detachedAssertRejectedWithHeaderError(t, detachedParseForRejection(t, payload, serializations), payload)
	})

	t.Run("b64 in unprotected header without crit", func(t *testing.T) {
		const protectedJSON = `{"alg":"HS256"}`
		serializations := newDetachedJSONWithUnprotected(
			protectedJSON, `{"b64":false}`,
			payload, detachedSignEncoded(t, protectedJSON, payload),
		)
		detachedAssertRejectedWithHeaderError(t, detachedParseForRejection(t, payload, serializations), payload)
	})

	testCases := []struct {
		name          string
		protectedJSON string
		signature     func(*testing.T, string, []byte) []byte
	}{
		{
			name:          "b64 false but the encoded payload was signed",
			protectedJSON: `{"alg":"HS256","b64":false,"crit":["b64"]}`,
			signature:     detachedSignEncoded,
		},
		{
			name:          "b64 true but the raw payload was signed",
			protectedJSON: `{"alg":"HS256","b64":true,"crit":["b64"]}`,
			signature:     detachedSignRaw,
		},
		{
			name:          "b64 absent but the raw payload was signed",
			protectedJSON: `{"alg":"HS256"}`,
			signature:     detachedSignRaw,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serializations := newDetachedSerializations(
				tc.protectedJSON, payload, tc.signature(t, tc.protectedJSON, payload),
			)
			detachedAssertRejected(t, detachedParseForRejection(t, payload, serializations), payload)
		})
	}

	t.Run("b64 is not a JSON boolean", func(t *testing.T) {
		// RFC 7797 section 3: "b64" is a JSON boolean, default true. A value
		// of another JSON type must not be coerced to true, because the
		// declaration then disagrees with the bytes that were signed. null is
		// rejected either as an invalid value or, when crit lists b64, as a
		// crit entry with no value.
		validHeaderError := func(err error) bool {
			return errors.Is(err, errInvalidB64Value) || errors.Is(err, ErrUnsupportedCriticalHeader)
		}
		for _, b64Value := range []string{`null`, `0`, `1`, `"false"`, `[false]`, `{}`} {
			protectedJSON := `{"alg":"HS256","b64":` + b64Value + `,"crit":["b64"]}`
			serializations := newDetachedSerializations(
				protectedJSON, payload, detachedSignEncoded(t, protectedJSON, payload),
			)
			objects := detachedParseForRejection(t, payload, serializations)
			if len(objects) == 0 {
				continue // rejected at parse time, which is also fine
			}
			for name, obj := range objects {
				if err := obj.DetachedVerify(payload, detachedTestKey); !validHeaderError(err) {
					t.Errorf("b64=%s (%s): DetachedVerify error = %v, want a header error", b64Value, name, err)
				}
				if _, err := obj.Verify(detachedTestKey); !validHeaderError(err) {
					t.Errorf("b64=%s (%s): Verify error = %v, want a header error", b64Value, name, err)
				}
			}
		}
	})

	t.Run("null b64 without crit", func(t *testing.T) {
		const protectedJSON = `{"alg":"HS256","b64":null}`
		serializations := newDetachedSerializations(
			protectedJSON, payload, detachedSignEncoded(t, protectedJSON, payload),
		)
		objects := detachedParseForRejection(t, payload, serializations)
		if len(objects) == 0 {
			return // rejected at parse time
		}
		for name, obj := range objects {
			if err := obj.DetachedVerify(payload, detachedTestKey); !errors.Is(err, errInvalidB64Value) {
				t.Errorf("%s: DetachedVerify error = %v, want %v", name, err, errInvalidB64Value)
			}
			if _, err := obj.Verify(detachedTestKey); !errors.Is(err, errInvalidB64Value) {
				t.Errorf("%s: Verify error = %v, want %v", name, err, errInvalidB64Value)
			}
		}
	})

	t.Run("signer rejects a non-boolean b64 header", func(t *testing.T) {
		for _, b64Value := range []any{0, "false", []bool{false}} {
			signer, err := NewSigner(SigningKey{Algorithm: HS256, Key: detachedTestKey},
				new(SignerOptions).WithHeader(headerB64, b64Value).WithCritical(headerB64))
			if err != nil {
				t.Fatalf("NewSigner with b64=%v: %v", b64Value, err)
			}
			if _, err := signer.Sign(payload); !errors.Is(err, errInvalidB64Value) {
				t.Errorf("Sign with b64=%v error = %v, want %v", b64Value, err, errInvalidB64Value)
			}
		}
	})
}

// TestDetachedPayloadPresenceRules checks that the entry points agree on whether
// a message is detached: a compact message that carries its own payload must
// not be accepted as detached, and an empty payload segment is the detached wire
// form.
func TestDetachedPayloadPresenceRules(t *testing.T) {
	payload := detachedBinaryPayload
	const protectedJSON = `{"alg":"HS256","b64":false,"crit":["b64"]}`
	serializations := newDetachedSerializations(
		protectedJSON, payload, detachedSign(t, protectedJSON, payload),
	)

	t.Run("compact with embedded payload is not detached", func(t *testing.T) {
		attached := base64.RawURLEncoding.EncodeToString([]byte(protectedJSON)) +
			"." + base64.RawURLEncoding.EncodeToString(payload) +
			"." + base64.RawURLEncoding.EncodeToString(detachedSign(t, protectedJSON, payload))

		obj, err := ParseSignedCompact(attached, []SignatureAlgorithm{HS256})
		if err != nil {
			t.Fatalf("ParseSignedCompact: %v", err)
		}
		if verified, err := obj.Verify(detachedTestKey); err != nil || !bytes.Equal(verified, payload) {
			t.Errorf("Verify returned (%q, %v), want (%q, nil)", verified, err, payload)
		}

		// ParseDetached asserts that the payload is external, so it must not
		// accept a message that carries one.
		if _, err := ParseDetached(attached, payload, []SignatureAlgorithm{HS256}); err == nil {
			t.Error("ParseDetached accepted a compact JWS that carries its own payload")
		}
		if _, err := ParseDetached(attached, bytes.Clone(payload), []SignatureAlgorithm{HS256}); err == nil {
			t.Error("ParseDetached accepted a compact JWS that carries its own payload")
		}
	})

	t.Run("nil detached payload is rejected", func(t *testing.T) {
		if _, err := ParseDetached(serializations.compact, nil, []SignatureAlgorithm{HS256}); err == nil {
			t.Error("ParseDetached accepted a nil payload")
		}
	})

	t.Run("empty payload segment is the detached wire form", func(t *testing.T) {
		obj, err := ParseDetached(serializations.compact, payload, []SignatureAlgorithm{HS256})
		if err != nil {
			t.Fatalf("ParseDetached: %v", err)
		}
		if err := obj.DetachedVerify(payload, detachedTestKey); err != nil {
			t.Errorf("DetachedVerify: %v", err)
		}

		// Parsed without an external payload, the same bytes are a message
		// with an empty payload; the signature does not cover the external
		// bytes, so verification must fail.
		empty, err := ParseSignedCompact(serializations.compact, []SignatureAlgorithm{HS256})
		if err != nil {
			t.Fatalf("ParseSignedCompact: %v", err)
		}
		if verified, err := empty.Verify(detachedTestKey); err == nil {
			t.Errorf("Verify accepted the detached wire form as an attached message, payload %q", verified)
		}
	})

	t.Run("JSON without a payload member is rejected", func(t *testing.T) {
		protected := base64.RawURLEncoding.EncodeToString([]byte(protectedJSON))
		encodedSignature := base64.RawURLEncoding.EncodeToString(detachedSign(t, protectedJSON, payload))
		for name, serialized := range map[string]string{
			"flattened": fmt.Sprintf(`{"protected":"%s","signature":"%s"}`, protected, encodedSignature),
			"general":   fmt.Sprintf(`{"signatures":[{"protected":"%s","signature":"%s"}]}`, protected, encodedSignature),
		} {
			if _, err := ParseSignedJSON(serialized, []SignatureAlgorithm{HS256}); err == nil {
				t.Errorf("ParseSignedJSON(%s) accepted a message without a payload", name)
			}
		}
	})
}
