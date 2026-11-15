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
	stdjson "encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test fixtures and helpers
// ---------------------------------------------------------------------------

// Symmetric keys used by the multi-recipient tests. Sizes match the key
// management algorithms they are used with.
var (
	bombKWKey128 = bytes.Repeat([]byte{0x11}, 16) // A128KW
	bombKWKey192 = bytes.Repeat([]byte{0x22}, 24) // A192KW
	bombKWKey256 = bytes.Repeat([]byte{0x33}, 32) // A256KW
	bombDirect32 = bytes.Repeat([]byte{0x44}, 32) // DIRECT with A256GCM
)

// bombRecipients are three distinct key-wrapping recipients used to exercise
// the multi-recipient (DecryptMulti) path.
var bombRecipients = []Recipient{
	{Algorithm: A128KW, Key: bombKWKey128, KeyID: "kw-128"},
	{Algorithm: A192KW, Key: bombKWKey192, KeyID: "kw-192"},
	{Algorithm: A256KW, Key: bombKWKey256, KeyID: "kw-256"},
}

// bombKeyByAlg maps each recipient's key management algorithm to the key that
// can unwrap its encrypted CEK.
var bombKeyByAlg = map[KeyAlgorithm][]byte{
	A128KW: bombKWKey128,
	A192KW: bombKWKey192,
	A256KW: bombKWKey256,
}

// mustInflateLimit mirrors the production budget in inflate(): the larger of
// 250_000 bytes or ten times the compressed input size.
func mustInflateLimit(compressedLen int) int64 {
	return max(250_000, 10*int64(compressedLen))
}

// mixedRatioStream builds a deterministic DEFLATE stream whose uncompressed
// output is randomPrefix followed by Q copies of fill. The random prefix keeps
// the compressed size large (so the 10x ratio branch of the budget is active),
// while the repeated tail adds arbitrarily much output for almost no extra
// compressed bytes.
func mixedRatioStream(t *testing.T, Q int) (data, compressed []byte) {
	t.Helper()
	rng := rand.New(rand.NewPCG(1, 2))
	const prefixLen = 26_000
	prefix := make([]byte, prefixLen)
	// Fill via the deterministic PRNG: math/rand/v2 Rand exposes Read on its
	// concrete *Rand type through ReadByte-style helpers, so use a loop.
	for i := range prefix {
		prefix[i] = byte(rng.Uint32())
	}
	data = make([]byte, 0, prefixLen+Q)
	data = append(data, prefix...)
	data = append(data, bytes.Repeat([]byte{0x5a}, Q)...)
	compressed, err := deflate(data)
	if err != nil {
		t.Fatalf("deflating mixed stream: %v", err)
	}
	return data, compressed
}

// encryptedJWEWithInner constructs a single- or multi-recipient JWE carrying
// inner (already DEFLATE-compressed, or malformed) content as ciphertext.
//
// It is equivalent to Encrypt()/EncryptWithAuthData() but lets the caller
// choose the exact inner bytes, which is necessary to embed a zip bomb, a
// truncated DEFLATE stream or corrupt bytes while keeping the AEAD tag valid
// (until the caller deliberately breaks it).
func encryptedJWEWithInner(
	t *testing.T,
	enc ContentEncryption,
	rcpts []Recipient,
	inner []byte,
) *JSONWebEncryption {
	t.Helper()

	var encrypter Encrypter
	var err error
	if len(rcpts) == 1 {
		encrypter, err = NewEncrypter(enc, rcpts[0], &EncrypterOptions{Compression: DEFLATE})
	} else {
		encrypter, err = NewMultiEncrypter(enc, rcpts, &EncrypterOptions{Compression: DEFLATE})
	}
	if err != nil {
		t.Fatalf("creating encrypter: %v", err)
	}
	ctx := encrypter.(*genericEncrypter)

	obj := &JSONWebEncryption{}
	obj.protected = &rawHeader{}
	if err := obj.protected.set(headerEncryption, ctx.contentAlg); err != nil {
		t.Fatalf("setting enc header: %v", err)
	}

	obj.recipients = make([]recipientInfo, len(ctx.recipients))
	cek, headers, err := ctx.keyGenerator.genKey()
	if err != nil {
		t.Fatalf("generating CEK: %v", err)
	}
	obj.protected.merge(&headers)

	for i, info := range ctx.recipients {
		recipient, err := info.keyEncrypter.encryptKey(cek, info.keyAlg)
		if err != nil {
			t.Fatalf("wrapping CEK for recipient %d: %v", i, err)
		}
		if err := recipient.header.set(headerAlgorithm, info.keyAlg); err != nil {
			t.Fatalf("setting alg header: %v", err)
		}
		if info.keyID != "" {
			if err := recipient.header.set(headerKeyID, info.keyID); err != nil {
				t.Fatalf("setting kid header: %v", err)
			}
		}
		obj.recipients[i] = recipient
	}

	if len(ctx.recipients) == 1 {
		// Match Encrypt(): single-recipient messages move per-recipient
		// headers into the protected header.
		obj.protected.merge(obj.recipients[0].header)
		obj.recipients[0].header = nil
	}

	if err := obj.protected.set(headerCompression, DEFLATE); err != nil {
		t.Fatalf("setting zip header: %v", err)
	}

	authData, err := obj.computeAuthData()
	if err != nil {
		t.Fatalf("computing auth data: %v", err)
	}
	parts, err := ctx.cipher.encrypt(cek, authData, inner)
	if err != nil {
		t.Fatalf("encrypting inner content: %v", err)
	}
	obj.iv = parts.iv
	obj.ciphertext = parts.ciphertext
	obj.tag = parts.tag
	return obj
}

// parseRoundtrip serializes obj as JWE JSON and parses it back, so tests
// exercise the real ParseEncrypted -> Decrypt/DecryptMulti code path rather
// than operating on an in-memory object.
func parseRoundtrip(t *testing.T, obj *JSONWebEncryption, keyAlgs []KeyAlgorithm) *JSONWebEncryption {
	t.Helper()
	parsed, err := ParseEncryptedJSON(
		obj.FullSerialize(),
		keyAlgs,
		[]ContentEncryption{obj.protected.getEncryption()},
	)
	if err != nil {
		t.Fatalf("parsing serialized JWE: %v", err)
	}
	return parsed
}

// flipFirstByte flips the first byte of a non-empty slice.
func flipFirstByte(b []byte) {
	if len(b) > 0 {
		b[0] ^= 0xff
	}
}

// ---------------------------------------------------------------------------
// 1. inflate() budget unit tests: budget is measured against the *real*
// decompressed output, and rejections never hand back partial plaintext.
// ---------------------------------------------------------------------------

// The absolute output cap is 250_000 bytes for small compressed inputs.
func TestInflateAbsoluteBudgetBoundary(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		outLen  int
		wantErr bool
	}{
		{"one byte under cap", 250_000 - 1, false},
		{"exactly at cap", 250_000, false},
		{"one byte over cap", 250_000 + 1, true},
		{"well over cap", 300_000, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Highly compressible zeros: the compressed payload is ~300 bytes
			// regardless of output length, so the 250_000 absolute cap is the
			// binding constraint, not the 10x ratio.
			want := make([]byte, tc.outLen)
			compressed, err := deflate(want)
			if err != nil {
				t.Fatalf("deflate: %v", err)
			}
			if int64(len(compressed))*10 > 250_000 {
				t.Fatalf("test setup invalid: ratio branch would bind (compressed=%d)", len(compressed))
			}

			got, err := inflate(compressed)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("inflate(%d output bytes): expected budget error, got nil; output len=%d", tc.outLen, len(got))
				}
				if !strings.Contains(err.Error(), "uncompressed data would be too large") {
					t.Fatalf("expected budget-limit error, got: %v", err)
				}
				// A rejection must not return partial plaintext.
				if got != nil {
					t.Fatalf("budget rejection returned %d bytes of partial plaintext", len(got))
				}
				return
			}
			if err != nil {
				t.Fatalf("inflate: unexpected error: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(got), len(want))
			}
		})
	}
}

// When the compressed input is large, the binding limit is 10x the compressed
// size rather than the 250_000 floor. These two streams straddle that boundary
// by exactly one byte while sharing an identical compressed size, proving the
// budget tracks the real decompressed output, not the compressed input size.
// The Q constants below were located by binary search over the deterministic
// mixed stream produced by mixedRatioStream, and are validated at runtime.
func TestInflateRatioBudgetBoundary(t *testing.T) {
	t.Parallel()

	// The first failing Q for the deterministic mixed stream: Q=248400 yields
	// 274_400 output bytes == 10 * 27_440 compressed bytes (allowed), and one
	// more output byte with the same compressed size is rejected.
	passData, passCompressed := mixedRatioStream(t, 248_400)
	failData, failCompressed := mixedRatioStream(t, 248_401)

	if len(passCompressed) != len(failCompressed) {
		t.Fatalf("test setup invalid: compressed sizes differ (%d vs %d); boundary is not controlled by output size",
			len(passCompressed), len(failCompressed))
	}
	limit := mustInflateLimit(len(passCompressed))
	if int64(len(passData)) != limit || int64(len(failData)) != limit+1 {
		t.Fatalf("test setup invalid: pass=%d fail=%d limit=%d", len(passData), len(failData), limit)
	}
	if limit <= 250_000 {
		t.Fatalf("test setup invalid: ratio branch not active, limit=%d", limit)
	}

	got, err := inflate(passCompressed)
	if err != nil {
		t.Fatalf("inflate at exact ratio limit: unexpected error: %v", err)
	}
	if !bytes.Equal(got, passData) {
		t.Fatalf("roundtrip mismatch at boundary: got %d bytes, want %d", len(got), len(passData))
	}

	got, err = inflate(failCompressed)
	if err == nil {
		t.Fatalf("inflate one byte over ratio limit: expected budget error, got nil; output len=%d", len(got))
	}
	if !strings.Contains(err.Error(), "uncompressed data would be too large") {
		t.Fatalf("expected budget-limit error, got: %v", err)
	}
	if got != nil {
		t.Fatalf("budget rejection returned %d bytes of partial plaintext", len(got))
	}
}

// A zip bomb and a truncated DEFLATE stream are both rejected, and every
// rejection returns nil output (no partial plaintext leaks).
func TestInflateBombAndTruncationRejectNoPartialOutput(t *testing.T) {
	t.Parallel()

	t.Run("zip bomb", func(t *testing.T) {
		t.Parallel()
		// 512k repeated bytes compress to under a kilobyte: a classic bomb.
		bomb := bytes.Repeat([]byte("a"), 512_000)
		compressed, err := deflate(bomb)
		if err != nil {
			t.Fatalf("deflate: %v", err)
		}
		if int64(len(compressed))*10 >= int64(len(bomb)) {
			t.Fatalf("test setup invalid: not a bomb (compressed=%d, plain=%d)", len(compressed), len(bomb))
		}
		out, err := inflate(compressed)
		if err == nil {
			t.Fatalf("expected error inflating zip bomb, got output of %d bytes", len(out))
		}
		if out != nil {
			t.Fatalf("zip bomb rejection leaked %d bytes of partial plaintext", len(out))
		}
	})

	t.Run("truncated stream", func(t *testing.T) {
		t.Parallel()
		complete, err := deflate(bytes.Repeat([]byte("b"), 300_000))
		if err != nil {
			t.Fatalf("deflate: %v", err)
		}
		for _, cut := range []int{1, 5, len(complete) / 2, len(complete) - 1} {
			truncated := complete[:cut]
			out, err := inflate(truncated)
			if err == nil {
				t.Fatalf("cut=%d: expected error on truncated DEFLATE stream, got %d bytes", cut, len(out))
			}
			if out != nil {
				t.Fatalf("cut=%d: truncated stream returned %d bytes of partial plaintext", cut, len(out))
			}
		}
	})

	t.Run("corrupt stream", func(t *testing.T) {
		t.Parallel()
		out, err := inflate([]byte{0x01, 0x02, 0x03, 0x04})
		if err == nil {
			t.Fatalf("expected error on corrupt DEFLATE stream, got %d bytes", len(out))
		}
		if out != nil {
			t.Fatalf("corrupt stream returned %d bytes of partial plaintext", len(out))
		}
	})
}

// Repeated inflate calls on the same offending input must fail identically:
// the boundary errors are deterministic, not flaky.
func TestInflateBudgetErrorIsStable(t *testing.T) {
	t.Parallel()

	_, overCap := mustZerosStream(t, 250_001)
	_, overRatio := mixedRatioStream(t, 248_401)

	for i := 0; i < 5; i++ {
		if out, err := inflate(overCap); err == nil || out != nil {
			t.Fatalf("iteration %d: absolute-cap error not stable (out=%d err=%v)", i, len(out), err)
		}
		if out, err := inflate(overRatio); err == nil || out != nil {
			t.Fatalf("iteration %d: ratio-cap error not stable (out=%d err=%v)", i, len(out), err)
		}
	}
}

func mustZerosStream(t *testing.T, n int) (data, compressed []byte) {
	t.Helper()
	data = make([]byte, n)
	compressed, err := deflate(data)
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}
	return data, compressed
}

// ---------------------------------------------------------------------------
// 2. Single-recipient JWE (Decrypt): end-to-end budget enforcement, no
// plaintext on rejection, and authentication ordered before decompression.
// ---------------------------------------------------------------------------

// A legitimate DEFLATE-compressed message round-trips at both sides of the
// absolute budget.
func TestSingleRecipientCompressedRoundtripBoundary(t *testing.T) {
	t.Parallel()

	rcpt := Recipient{Algorithm: DIRECT, Key: bombDirect32}
	for _, n := range []int{250_000 - 1, 250_000} {
		t.Run(fmt.Sprintf("plaintext=%d", n), func(t *testing.T) {
			t.Parallel()
			plaintext := bytes.Repeat([]byte("z"), n)
			enc, err := NewEncrypter(A256GCM, rcpt, &EncrypterOptions{Compression: DEFLATE})
			if err != nil {
				t.Fatalf("NewEncrypter: %v", err)
			}
			obj, err := enc.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			parsed := parseRoundtrip(t, obj, []KeyAlgorithm{DIRECT})

			got, err := parsed.Decrypt(bombDirect32)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(got), len(plaintext))
			}
		})
	}
}

// A JWE whose authenticated plaintext is a zip bomb is rejected by the
// decompression budget, and Decrypt returns no partial plaintext.
func TestSingleRecipientZipBombRejected(t *testing.T) {
	t.Parallel()

	bombPlaintext := bytes.Repeat([]byte("a"), 512_000)
	inner, err := deflate(bombPlaintext)
	if err != nil {
		t.Fatalf("deflate bomb: %v", err)
	}
	obj := encryptedJWEWithInner(t, A256GCM,
		[]Recipient{{Algorithm: DIRECT, Key: bombDirect32}}, inner)
	parsed := parseRoundtrip(t, obj, []KeyAlgorithm{DIRECT})

	out, err := parsed.Decrypt(bombDirect32)
	if err == nil {
		t.Fatalf("expected error decrypting bomb JWE, got %d bytes", len(out))
	}
	if !strings.Contains(err.Error(), "uncompressed data would be too large") {
		t.Fatalf("expected decompression-budget error, got: %v", err)
	}
	if out != nil {
		t.Fatalf("bomb rejection returned %d bytes of partial plaintext", len(out))
	}
}

// A truncated DEFLATE stream authenticated as the JWE plaintext is rejected
// with a decompression (not crypto) error, again without partial output.
func TestSingleRecipientTruncatedDeflateRejected(t *testing.T) {
	t.Parallel()

	complete, err := deflate(bytes.Repeat([]byte("b"), 10_000))
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}
	inner := complete[:len(complete)/2]
	obj := encryptedJWEWithInner(t, A256GCM,
		[]Recipient{{Algorithm: DIRECT, Key: bombDirect32}}, inner)
	parsed := parseRoundtrip(t, obj, []KeyAlgorithm{DIRECT})

	out, err := parsed.Decrypt(bombDirect32)
	if err == nil {
		t.Fatalf("expected error decrypting truncated-stream JWE, got %d bytes", len(out))
	}
	if !strings.Contains(err.Error(), "failed to decompress plaintext") {
		t.Fatalf("expected decompression error, got: %v", err)
	}
	if out != nil {
		t.Fatalf("truncated-stream rejection returned %d bytes of partial plaintext", len(out))
	}
}

// Authentication must complete before any decompression result becomes
// observable. A bad tag on a message that *would* trip the decompression bomb
// produces a crypto failure, never a decompression error, and never plaintext.
func TestSingleRecipientBadTagBypassesDecompression(t *testing.T) {
	t.Parallel()

	// Two flavors of decompression-hostile inner content, each wrapped with a
	// valid tag which we then corrupt.
	cases := []struct {
		name  string
		inner []byte
	}{
		{"zip bomb behind bad tag", mustCompressed(t, bytes.Repeat([]byte("a"), 512_000))},
		{"truncated DEFLATE behind bad tag", truncateHalf(t, mustCompressed(t, bytes.Repeat([]byte("b"), 10_000)))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			obj := encryptedJWEWithInner(t, A256GCM,
				[]Recipient{{Algorithm: DIRECT, Key: bombDirect32}}, tc.inner)
			flipFirstByte(obj.tag)
			parsed := parseRoundtrip(t, obj, []KeyAlgorithm{DIRECT})

			out, err := parsed.Decrypt(bombDirect32)
			if !errors.Is(err, ErrCryptoFailure) {
				t.Fatalf("expected ErrCryptoFailure, got %v (output len=%d)", err, len(out))
			}
			if strings.Contains(err.Error(), "decompress") {
				t.Fatalf("decompression result observable before authentication completed: %v", err)
			}
			if out != nil {
				t.Fatalf("auth failure returned %d bytes of plaintext", len(out))
			}
		})
	}
}

// A corrupted ciphertext likewise fails authentication without decompressing.
func TestSingleRecipientBadCiphertextIsCryptoFailure(t *testing.T) {
	t.Parallel()

	inner := mustCompressed(t, bytes.Repeat([]byte("a"), 512_000))
	obj := encryptedJWEWithInner(t, A256GCM,
		[]Recipient{{Algorithm: DIRECT, Key: bombDirect32}}, inner)
	flipFirstByte(obj.ciphertext)
	parsed := parseRoundtrip(t, obj, []KeyAlgorithm{DIRECT})

	out, err := parsed.Decrypt(bombDirect32)
	if !errors.Is(err, ErrCryptoFailure) {
		t.Fatalf("expected ErrCryptoFailure, got %v", err)
	}
	if out != nil {
		t.Fatalf("auth failure returned %d bytes of plaintext", len(out))
	}
}

// Boundary/error behavior must reproduce identically across repeated runs.
func TestSingleRecipientErrorsAreStable(t *testing.T) {
	t.Parallel()

	inner, err := deflate(bytes.Repeat([]byte("a"), 512_000))
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}
	obj := encryptedJWEWithInner(t, A256GCM,
		[]Recipient{{Algorithm: DIRECT, Key: bombDirect32}}, inner)
	parsed := parseRoundtrip(t, obj, []KeyAlgorithm{DIRECT})

	var firstErr string
	for i := 0; i < 3; i++ {
		out, err := parsed.Decrypt(bombDirect32)
		if err == nil || out != nil {
			t.Fatalf("iteration %d: bomb unexpectedly accepted (out=%d)", i, len(out))
		}
		if firstErr == "" {
			firstErr = err.Error()
		} else if err.Error() != firstErr {
			t.Fatalf("iteration %d: error changed:\n first=%s\n now=%s", i, firstErr, err.Error())
		}
	}
}

func mustCompressed(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	compressed, err := deflate(plaintext)
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}
	return compressed
}

func truncateHalf(t *testing.T, compressed []byte) []byte {
	t.Helper()
	if len(compressed) < 2 {
		t.Fatal("compressed stream too short to truncate")
	}
	return compressed[:len(compressed)/2]
}

// ---------------------------------------------------------------------------
// 3. Multi-recipient JWE (DecryptMulti): every recipient recovers the exact
// original bytes regardless of ordering, and the same security properties hold.
// ---------------------------------------------------------------------------

// A legitimate compressed message decrypts to identical bytes for every
// recipient under every permutation of the recipient list.
func TestMultiRecipientCompressedRoundtripPermutations(t *testing.T) {
	t.Parallel()

	plaintext := bytes.Repeat([]byte("multi-recipient payload "), 2_000) // ~46k, under budget
	enc, err := NewMultiEncrypter(A256GCM, bombRecipients, &EncrypterOptions{Compression: DEFLATE})
	if err != nil {
		t.Fatalf("NewMultiEncrypter: %v", err)
	}
	obj, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	serialized := obj.FullSerialize()

	// Baseline ordering of kid values on the wire.
	baselineKids, err := recipientKIDs(serialized)
	if err != nil {
		t.Fatalf("reading baseline recipients: %v", err)
	}

	for _, wirePerm := range permutations(len(bombRecipients)) {
		wirePerm := wirePerm
		t.Run(fmt.Sprintf("wire_order=%v", wirePerm), func(t *testing.T) {
			t.Parallel()

			reordered, err := reorderSerializedRecipients(serialized, wirePerm)
			if err != nil {
				t.Fatalf("reordering recipients: %v", err)
			}
			// The ground-truth wire position of each kid, read back from the
			// reordered envelope rather than derived from permutation math.
			wireKids, err := recipientKIDs(reordered)
			if err != nil {
				t.Fatalf("reading reordered recipients: %v", err)
			}
			wantIndexByKid := make(map[string]int, len(wireKids))
			for i, kid := range wireKids {
				wantIndexByKid[kid] = i
			}

			parsed, err := ParseEncryptedJSON(reordered,
				[]KeyAlgorithm{A128KW, A192KW, A256KW}, []ContentEncryption{A256GCM})
			if err != nil {
				t.Fatalf("ParseEncryptedJSON: %v", err)
			}

			// Every recipient key must recover the exact original plaintext.
			for _, alg := range []KeyAlgorithm{A128KW, A192KW, A256KW} {
				key := bombKeyByAlg[alg]
				index, hdr, got, err := parsed.DecryptMulti(key)
				if err != nil {
					t.Fatalf("DecryptMulti with %s: %v", alg, err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("%s: decrypted %d bytes, want %d", alg, len(got), len(plaintext))
				}
				if index != wantIndexByKid[hdr.KeyID] {
					t.Fatalf("%s: reported recipient index %d, want %d (kid=%q)",
						alg, index, wantIndexByKid[hdr.KeyID], hdr.KeyID)
				}
			}

			// The permutation must have actually moved recipients relative to
			// the baseline when it is non-identity, proving the reorder helper
			// and the index accounting are doing real work.
			identity := true
			for i := range wireKids {
				if wireKids[i] != baselineKids[i] {
					identity = false
					break
				}
			}
			isIdentityPerm := true
			for i, p := range wirePerm {
				if p != i {
					isIdentityPerm = false
					break
				}
			}
			if identity != isIdentityPerm {
				t.Fatalf("permutation %v did not produce the expected wire reordering: %v", wirePerm, wireKids)
			}
		})
	}
}

// A zip bomb delivered to a multi-recipient JWE is rejected for every
// recipient, and the failure returns no plaintext.
func TestMultiRecipientZipBombRejected(t *testing.T) {
	t.Parallel()

	inner, err := deflate(bytes.Repeat([]byte("a"), 512_000))
	if err != nil {
		t.Fatalf("deflate bomb: %v", err)
	}
	obj := encryptedJWEWithInner(t, A256GCM, bombRecipients, inner)
	parsed := parseRoundtrip(t, obj, []KeyAlgorithm{A128KW, A192KW, A256KW})

	for alg, key := range bombKeyByAlg {
		index, _, out, err := parsed.DecryptMulti(key)
		if err == nil {
			t.Fatalf("%s: expected bomb error, got %d bytes", alg, len(out))
		}
		if !strings.Contains(err.Error(), "uncompressed data would be too large") {
			t.Fatalf("%s: expected decompression-budget error, got: %v", alg, err)
		}
		if index != -1 {
			t.Fatalf("%s: expected index -1 on failure, got %d", alg, index)
		}
		if out != nil {
			t.Fatalf("%s: bomb rejection returned %d bytes of partial plaintext", alg, len(out))
		}
	}
}

// A truncated DEFLATE stream in a multi-recipient JWE is rejected at
// decompression for every recipient.
func TestMultiRecipientTruncatedDeflateRejected(t *testing.T) {
	t.Parallel()

	complete, err := deflate(bytes.Repeat([]byte("b"), 10_000))
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}
	obj := encryptedJWEWithInner(t, A256GCM, bombRecipients, complete[:len(complete)/2])
	parsed := parseRoundtrip(t, obj, []KeyAlgorithm{A128KW, A192KW, A256KW})

	for alg, key := range bombKeyByAlg {
		index, _, out, err := parsed.DecryptMulti(key)
		if err == nil {
			t.Fatalf("%s: expected truncated-stream error, got %d bytes", alg, len(out))
		}
		if !strings.Contains(err.Error(), "failed to decompress plaintext") {
			t.Fatalf("%s: expected decompression error, got: %v", alg, err)
		}
		if index != -1 || out != nil {
			t.Fatalf("%s: expected index -1 and nil output, got index=%d out=%d", alg, index, len(out))
		}
	}
}

// A bad authentication tag in a multi-recipient JWE must fail AEAD validation
// for every recipient before decompression runs: ErrCryptoFailure, never a
// decompression error, never plaintext.
func TestMultiRecipientBadTagBypassesDecompression(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		inner []byte
	}{
		{"zip bomb behind bad tag", mustCompressed(t, bytes.Repeat([]byte("a"), 512_000))},
		{"truncated DEFLATE behind bad tag", truncateHalf(t, mustCompressed(t, bytes.Repeat([]byte("b"), 10_000)))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			obj := encryptedJWEWithInner(t, A256GCM, bombRecipients, tc.inner)
			flipFirstByte(obj.tag)
			parsed := parseRoundtrip(t, obj, []KeyAlgorithm{A128KW, A192KW, A256KW})

			for alg, key := range bombKeyByAlg {
				index, _, out, err := parsed.DecryptMulti(key)
				if !errors.Is(err, ErrCryptoFailure) {
					t.Fatalf("%s: expected ErrCryptoFailure, got %v", alg, err)
				}
				if strings.Contains(err.Error(), "decompress") {
					t.Fatalf("%s: decompression observable before auth completed: %v", alg, err)
				}
				if index != -1 || out != nil {
					t.Fatalf("%s: expected no result, got index=%d out=%d", alg, index, len(out))
				}
			}
		})
	}
}

// A corrupted ciphertext is an AEAD failure, not a decompression outcome.
func TestMultiRecipientBadCiphertextIsCryptoFailure(t *testing.T) {
	t.Parallel()

	inner := mustCompressed(t, bytes.Repeat([]byte("a"), 512_000))
	obj := encryptedJWEWithInner(t, A256GCM, bombRecipients, inner)
	flipFirstByte(obj.ciphertext)
	parsed := parseRoundtrip(t, obj, []KeyAlgorithm{A128KW, A192KW, A256KW})

	for alg, key := range bombKeyByAlg {
		index, _, out, err := parsed.DecryptMulti(key)
		if !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("%s: expected ErrCryptoFailure, got %v", alg, err)
		}
		if index != -1 || out != nil {
			t.Fatalf("%s: expected no result, got index=%d out=%d", alg, index, len(out))
		}
	}
}

// All multi-recipient error conditions reproduce across repeated attempts.
func TestMultiRecipientErrorsAreStable(t *testing.T) {
	t.Parallel()

	inner, err := deflate(bytes.Repeat([]byte("a"), 512_000))
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}
	obj := encryptedJWEWithInner(t, A256GCM, bombRecipients, inner)
	parsed := parseRoundtrip(t, obj, []KeyAlgorithm{A128KW, A192KW, A256KW})

	for alg, key := range bombKeyByAlg {
		var firstErr string
		for i := 0; i < 3; i++ {
			index, _, out, err := parsed.DecryptMulti(key)
			if err == nil || out != nil || index != -1 {
				t.Fatalf("%s iteration %d: unexpected success (index=%d out=%d err=%v)", alg, i, index, len(out), err)
			}
			if firstErr == "" {
				firstErr = err.Error()
			} else if err.Error() != firstErr {
				t.Fatalf("%s iteration %d: error changed:\n first=%s\n now=%s", alg, i, firstErr, err.Error())
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Small generic helpers (kept local to this test file).
// ---------------------------------------------------------------------------

// permutations returns every permutation of indices [0..n).
func permutations(n int) [][]int {
	var out [][]int
	idx := make([]int, n)
	for i := range idx {
		idx[i] = i
	}
	var rec func(int)
	rec = func(k int) {
		if k == 1 {
			perm := make([]int, n)
			copy(perm, idx)
			out = append(out, perm)
			return
		}
		rec(k - 1)
		for i := 0; i < k-1; i++ {
			if k%2 == 0 {
				idx[i], idx[k-1] = idx[k-1], idx[i]
			} else {
				idx[0], idx[k-1] = idx[k-1], idx[0]
			}
			rec(k - 1)
		}
	}
	rec(n)
	return out
}

// reorderSerializedRecipients parses a full-serialization JWE JSON string and
// reorders its recipients array according to order (a permutation of indices).
//
// Uses the standard library JSON package: this is test-only structural
// manipulation of the envelope, not the library's parser under test.
func reorderSerializedRecipients(serialized string, order []int) (string, error) {
	var raw map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal([]byte(serialized), &raw); err != nil {
		return "", err
	}
	var recipients []map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(raw["recipients"], &recipients); err != nil {
		return "", err
	}
	if len(recipients) != len(order) {
		return "", fmt.Errorf("order length %d does not match %d recipients", len(order), len(recipients))
	}
	// order[i] is the new wire position of the recipient currently at
	// position i, i.e. shuffled[order[i]] = recipients[i].
	shuffled := make([]map[string]stdjson.RawMessage, len(recipients))
	for i, newPos := range order {
		shuffled[newPos] = recipients[i]
	}
	reordered, err := stdjson.Marshal(shuffled)
	if err != nil {
		return "", err
	}
	raw["recipients"] = reordered
	out, err := stdjson.Marshal(raw)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// recipientKIDs reads the per-recipient "kid" header values from a
// full-serialization JWE JSON string, in wire order.
func recipientKIDs(serialized string) ([]string, error) {
	var raw struct {
		Recipients []struct {
			Header struct {
				KeyID string `json:"kid"`
			} `json:"header"`
		} `json:"recipients"`
	}
	if err := stdjson.Unmarshal([]byte(serialized), &raw); err != nil {
		return nil, err
	}
	out := make([]string, len(raw.Recipients))
	for i, r := range raw.Recipients {
		out[i] = r.Header.KeyID
	}
	return out, nil
}
