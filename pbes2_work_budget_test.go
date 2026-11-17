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
	"errors"
	"strings"
	"testing"
)

// withPBES2WorkLimit runs a test with MaxPBES2Work set to limit, restoring the
// previous value afterwards.
func withPBES2WorkLimit(t *testing.T, limit int, fn func()) {
	t.Helper()
	previous := MaxPBES2Work
	MaxPBES2Work = limit
	defer func() { MaxPBES2Work = previous }()
	fn()
}

// encryptPBES2Multi builds a multi-recipient JWE whose recipients are all
// password-based, using the given (password, p2c) pairs in order, and parses
// it back so tests exercise the real decrypt path.
func encryptPBES2Multi(t *testing.T, recipients []Recipient) *JSONWebEncryption {
	t.Helper()

	enc, err := NewMultiEncrypter(A128GCM, recipients, nil)
	if err != nil {
		t.Fatalf("NewMultiEncrypter: %v", err)
	}
	obj, err := enc.Encrypt([]byte("Lorem ipsum dolor sit amet"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	parsed, err := ParseEncryptedJSON(obj.FullSerialize(),
		[]KeyAlgorithm{PBES2_HS256_A128KW}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatalf("ParseEncryptedJSON: %v", err)
	}
	return parsed
}

func pbes2Recipient(password string, p2c int) Recipient {
	return Recipient{Algorithm: PBES2_HS256_A128KW, Key: password, PBES2Count: p2c}
}

// A recipient whose headers would be rejected before a key derivation is
// charged nothing, so rejected and malformed recipients cannot be used to
// exhaust the budget of the recipients that follow.
func TestPBES2WorkBudgetCostlessRejections(t *testing.T) {
	budget := newPBES2WorkBudget()
	symmetric := &symmetricKeyCipher{key: []byte("password")}

	header := func(alg KeyAlgorithm, p2s *byteBuffer, p2c int) rawHeader {
		h := rawHeader{}
		if alg != "" {
			if err := h.set(headerAlgorithm, alg); err != nil {
				t.Fatalf("setting alg: %v", err)
			}
		}
		if p2s != nil {
			if err := h.set(headerP2S, p2s); err != nil {
				t.Fatalf("setting p2s: %v", err)
			}
		}
		if p2c != 0 {
			if err := h.set(headerP2C, p2c); err != nil {
				t.Fatalf("setting p2c: %v", err)
			}
		}
		return h
	}

	validRecipient := &recipientInfo{encryptedKey: bytes.Repeat([]byte{0x01}, 24)}
	emptyRecipient := &recipientInfo{}

	cases := []struct {
		name      string
		decrypter keyDecrypter
		header    rawHeader
		recipient *recipientInfo
	}{
		{"non symmetric decrypter", &rsaDecrypterSigner{}, header(PBES2_HS256_A128KW, newBuffer([]byte("salt")), 500000), validRecipient},
		{"non PBES2 algorithm", symmetric, header(A256KW, newBuffer([]byte("salt")), 500000), validRecipient},
		{"missing p2s", symmetric, header(PBES2_HS256_A128KW, nil, 500000), validRecipient},
		{"missing p2c", symmetric, header(PBES2_HS256_A128KW, newBuffer([]byte("salt")), 0), validRecipient},
		{"p2c over per-item limit", symmetric, header(PBES2_HS256_A128KW, newBuffer([]byte("salt")), maxP2C+1), validRecipient},
		{"missing encrypted key", symmetric, header(PBES2_HS256_A128KW, newBuffer([]byte("salt")), 500000), emptyRecipient},
		{"nil recipient", symmetric, header(PBES2_HS256_A128KW, newBuffer([]byte("salt")), 500000), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !budget.spend(tc.decrypter, tc.header, tc.recipient) {
				t.Fatalf("expected costless rejection, but budget was charged")
			}
			if budget.remaining != MaxPBES2Work {
				t.Fatalf("budget changed by rejected recipient: remaining=%d, want %d", budget.remaining, MaxPBES2Work)
			}
		})
	}
}

// A derivation that does run is charged, exactly at the boundary, and a
// derivation that does not fit is refused without changing the budget.
func TestPBES2WorkBudgetCharging(t *testing.T) {
	symmetric := &symmetricKeyCipher{key: []byte("password")}
	header := rawHeader{}
	if err := header.set(headerAlgorithm, PBES2_HS256_A128KW); err != nil {
		t.Fatalf("setting alg: %v", err)
	}
	if err := header.set(headerP2S, newBuffer([]byte("salt"))); err != nil {
		t.Fatalf("setting p2s: %v", err)
	}
	if err := header.set(headerP2C, 1000); err != nil {
		t.Fatalf("setting p2c: %v", err)
	}
	recipient := &recipientInfo{encryptedKey: bytes.Repeat([]byte{0x01}, 24)}

	withPBES2WorkLimit(t, 1000, func() {
		budget := newPBES2WorkBudget()
		if !budget.spend(symmetric, header, recipient) {
			t.Fatal("a derivation equal to the remaining budget must be allowed")
		}
		if budget.remaining != 0 {
			t.Fatalf("remaining = %d, want 0", budget.remaining)
		}
		if budget.spend(symmetric, header, recipient) {
			t.Fatal("a derivation over the remaining budget must be refused")
		}
		if budget.remaining != 0 {
			t.Fatalf("refused derivation changed the budget: remaining = %d", budget.remaining)
		}
	})
}

// Every PBES2 derivation in one DecryptMulti call comes out of a single
// budget, so a later legitimate recipient is reached only if the decoys before
// it left enough. The failure of the budget is distinguishable from a wrong
// password.
func TestDecryptMultiPBES2SharedBudget(t *testing.T) {
	recipients := []Recipient{
		pbes2Recipient("first", 1000),
		pbes2Recipient("second", 1000),
		pbes2Recipient("third", 1000),
	}
	obj := encryptPBES2Multi(t, recipients)

	t.Run("legitimate recipient within budget", func(t *testing.T) {
		withPBES2WorkLimit(t, 3000, func() {
			index, _, plaintext, err := obj.DecryptMulti("third")
			if err != nil {
				t.Fatalf("DecryptMulti: %v", err)
			}
			if index != 2 {
				t.Fatalf("recipient index = %d, want 2", index)
			}
			if string(plaintext) != "Lorem ipsum dolor sit amet" {
				t.Fatalf("plaintext = %q", plaintext)
			}
		})
	})

	t.Run("budget stops before later legitimate recipient", func(t *testing.T) {
		withPBES2WorkLimit(t, 2500, func() {
			_, _, plaintext, err := obj.DecryptMulti("third")
			if !errors.Is(err, ErrPBES2WorkLimit) {
				t.Fatalf("DecryptMulti error = %v, want ErrPBES2WorkLimit", err)
			}
			if errors.Is(err, ErrCryptoFailure) {
				t.Fatalf("budget rejection must not be reported as a crypto failure: %v", err)
			}
			if plaintext != nil {
				t.Fatalf("budget rejection returned %d bytes of plaintext", len(plaintext))
			}
		})
	})

	t.Run("wrong password within budget is a crypto failure", func(t *testing.T) {
		withPBES2WorkLimit(t, 3000, func() {
			_, _, _, err := obj.DecryptMulti("wrong")
			if !errors.Is(err, ErrCryptoFailure) {
				t.Fatalf("DecryptMulti error = %v, want ErrCryptoFailure", err)
			}
			if errors.Is(err, ErrPBES2WorkLimit) {
				t.Fatalf("wrong password must not be reported as a budget rejection: %v", err)
			}
		})
	})

	t.Run("raising the budget admits the recipient", func(t *testing.T) {
		withPBES2WorkLimit(t, 2000, func() {
			if _, _, _, err := obj.DecryptMulti("third"); !errors.Is(err, ErrPBES2WorkLimit) {
				t.Fatalf("expected ErrPBES2WorkLimit at budget 2000, got %v", err)
			}
			MaxPBES2Work = 3000
			index, _, plaintext, err := obj.DecryptMulti("third")
			if err != nil {
				t.Fatalf("DecryptMulti after raising budget: %v", err)
			}
			if index != 2 || string(plaintext) != "Lorem ipsum dolor sit amet" {
				t.Fatalf("index = %d, plaintext = %q", index, plaintext)
			}
		})
	})
}

// Cheap failures — a malformed p2c and a non-PBES2 recipient whose key wrap
// fails immediately — must not consume the shared budget, so a later
// legitimate PBES2 recipient still decrypts with a budget that fits only it.
func TestDecryptMultiPBES2CheapFailuresDoNotSpendBudget(t *testing.T) {
	tooExpensive := pbes2Recipient("first", maxP2C+1)
	aesKW := Recipient{Algorithm: A256KW, Key: bytes.Repeat([]byte{0x42}, 32)}
	legit := pbes2Recipient("legit", 1000)

	enc, err := NewMultiEncrypter(A128GCM, []Recipient{tooExpensive, aesKW, legit}, nil)
	if err != nil {
		t.Fatalf("NewMultiEncrypter: %v", err)
	}
	obj, err := enc.Encrypt([]byte("Lorem ipsum dolor sit amet"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parsed, err := ParseEncryptedJSON(obj.FullSerialize(),
		[]KeyAlgorithm{PBES2_HS256_A128KW, A256KW}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatalf("ParseEncryptedJSON: %v", err)
	}

	withPBES2WorkLimit(t, 1000, func() {
		index, _, plaintext, err := parsed.DecryptMulti("legit")
		if err != nil {
			t.Fatalf("DecryptMulti: %v", err)
		}
		if index != 2 {
			t.Fatalf("recipient index = %d, want 2", index)
		}
		if string(plaintext) != "Lorem ipsum dolor sit amet" {
			t.Fatalf("plaintext = %q", plaintext)
		}
	})
}

// A message whose recipients all demand more work than the remaining budget
// reports the budget rejection instead of a wrong-password failure, even
// though no password was ever tried.
func TestDecryptMultiPBES2AllSkippedByBudget(t *testing.T) {
	obj := encryptPBES2Multi(t, []Recipient{
		pbes2Recipient("first", 1000),
		pbes2Recipient("second", 1000),
	})

	withPBES2WorkLimit(t, 500, func() {
		_, _, plaintext, err := obj.DecryptMulti("first")
		if !errors.Is(err, ErrPBES2WorkLimit) {
			t.Fatalf("DecryptMulti error = %v, want ErrPBES2WorkLimit", err)
		}
		if plaintext != nil {
			t.Fatalf("budget rejection returned %d bytes of plaintext", len(plaintext))
		}
	})
}

// The single-recipient Decrypt path uses the same budget, so a configured
// limit below the only recipient's p2c is reported distinctly from a wrong
// password, and raising it lets the message decrypt.
func TestDecryptPBES2WorkBudget(t *testing.T) {
	obj := encryptPBES2Multi(t, []Recipient{pbes2Recipient("password", 1000)})

	withPBES2WorkLimit(t, 999, func() {
		_, err := obj.Decrypt("password")
		if !errors.Is(err, ErrPBES2WorkLimit) {
			t.Fatalf("Decrypt error = %v, want ErrPBES2WorkLimit", err)
		}

		MaxPBES2Work = 1000
		plaintext, err := obj.Decrypt("password")
		if err != nil {
			t.Fatalf("Decrypt at exact budget: %v", err)
		}
		if string(plaintext) != "Lorem ipsum dolor sit amet" {
			t.Fatalf("plaintext = %q", plaintext)
		}
	})
}

// The per-recipient p2c limit is unchanged and is enforced before the budget:
// an over-limit recipient is rejected as before (not as a budget rejection)
// and spends nothing.
func TestPBES2PerItemLimitStillEnforced(t *testing.T) {
	obj := encryptPBES2Multi(t, []Recipient{pbes2Recipient("password", maxP2C+1)})

	withPBES2WorkLimit(t, 1, func() {
		_, err := obj.Decrypt("password")
		if err == nil {
			t.Fatal("expected over-limit p2c to be rejected")
		}
		if errors.Is(err, ErrPBES2WorkLimit) {
			t.Fatalf("over-limit p2c must be rejected independently of the budget, got %v", err)
		}
		if !errors.Is(err, ErrCryptoFailure) {
			t.Fatalf("Decrypt error = %v, want ErrCryptoFailure", err)
		}
	})
}

// A non-PBES2 recipient that legitimately follows several over-budget PBES2
// recipients still decrypts: the expensive derivations that do not fit are
// skipped without running, and only the affordable recipient does work.
func TestDecryptMultiPBES2BudgetDoesNotBlockLaterAsymmetricRecipient(t *testing.T) {
	expensive := make([]Recipient, 4)
	for i := range expensive {
		expensive[i] = pbes2Recipient("decoy", 1000)
	}
	rsaRecipient := Recipient{Algorithm: RSA_OAEP, Key: &rsaTestKey.PublicKey}
	recipients := append(append([]Recipient{}, expensive...), rsaRecipient)

	enc, err := NewMultiEncrypter(A128GCM, recipients, nil)
	if err != nil {
		t.Fatalf("NewMultiEncrypter: %v", err)
	}
	obj, err := enc.Encrypt([]byte("Lorem ipsum dolor sit amet"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parsed, err := ParseEncryptedJSON(obj.FullSerialize(),
		[]KeyAlgorithm{PBES2_HS256_A128KW, RSA_OAEP}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatalf("ParseEncryptedJSON: %v", err)
	}

	withPBES2WorkLimit(t, 2000, func() {
		index, _, plaintext, err := parsed.DecryptMulti(rsaTestKey)
		if err != nil {
			t.Fatalf("DecryptMulti: %v", err)
		}
		if index != len(expensive) {
			t.Fatalf("recipient index = %d, want %d", index, len(expensive))
		}
		if string(plaintext) != "Lorem ipsum dolor sit amet" {
			t.Fatalf("plaintext = %q", plaintext)
		}
	})
}

// The budget is per decryption call, not per message: a second call starts
// with the full budget again.
func TestDecryptMultiPBES2BudgetResetsPerCall(t *testing.T) {
	obj := encryptPBES2Multi(t, []Recipient{
		pbes2Recipient("first", 1000),
		pbes2Recipient("second", 1000),
	})

	withPBES2WorkLimit(t, 2000, func() {
		for attempt := 0; attempt < 3; attempt++ {
			index, _, plaintext, err := obj.DecryptMulti("second")
			if err != nil {
				t.Fatalf("attempt %d: DecryptMulti: %v", attempt, err)
			}
			if index != 1 || string(plaintext) != "Lorem ipsum dolor sit amet" {
				t.Fatalf("attempt %d: index = %d, plaintext = %q", attempt, index, plaintext)
			}
		}
	})
}

// An expensive recipient that is itself within the per-item limit but does not
// fit the remaining budget is skipped without deriving, and a later affordable
// legitimate recipient still decrypts with the remaining budget.
func TestDecryptMultiPBES2SkippedRecipientAllowsLaterCheapRecipient(t *testing.T) {
	obj := encryptPBES2Multi(t, []Recipient{
		pbes2Recipient("expensive-decoy", 9000),
		pbes2Recipient("legit", 500),
	})

	withPBES2WorkLimit(t, 1000, func() {
		index, _, plaintext, err := obj.DecryptMulti("legit")
		if err != nil {
			t.Fatalf("DecryptMulti: %v", err)
		}
		if index != 1 {
			t.Fatalf("recipient index = %d, want 1", index)
		}
		if string(plaintext) != "Lorem ipsum dolor sit amet" {
			t.Fatalf("plaintext = %q", plaintext)
		}
	})
}

// The existing recipient-count limit is independent of the work budget: a
// message over MaxRecipients is still rejected at parse time, before any
// decryption budget is consulted.
func TestPBES2WorkBudgetKeepsRecipientCountLimit(t *testing.T) {
	defer func(old int) { MaxRecipients = old }(MaxRecipients)

	MaxRecipients = 2
	recs := []Recipient{
		pbes2Recipient("a", 1000),
		pbes2Recipient("b", 1000),
		pbes2Recipient("c", 1000),
	}
	enc, err := NewMultiEncrypter(A128GCM, recs, nil)
	if err != nil {
		t.Fatalf("NewMultiEncrypter: %v", err)
	}
	obj, err := enc.Encrypt([]byte("payload"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = ParseEncryptedJSON(obj.FullSerialize(),
		[]KeyAlgorithm{PBES2_HS256_A128KW}, []ContentEncryption{A128GCM})
	if err == nil || !strings.Contains(err.Error(), "too many recipients") {
		t.Fatalf("parse error = %v, want too many recipients", err)
	}
}

// A hostile message can declare more maximum-cost PBES2 recipients than the
// budget can pay for: only the recipients the budget covers are derived, and
// the rest are skipped, so the message's cost stays bounded however many
// recipients it lists. The encrypted keys here are junk, so every derivation
// that does run fails.
func TestDecryptMultiPBES2ManyExpensiveRecipientsRejectedCheaply(t *testing.T) {
	b64 := func(n int) string {
		return newBuffer(bytes.Repeat([]byte{0x01}, n)).base64()
	}

	recipient := `{"header":{"alg":"PBES2-HS256+A128KW","p2c":1000000,"p2s":"` + b64(16) +
		`"},"encrypted_key":"` + b64(24) + `"}`
	recipients := make([]string, 5)
	for i := range recipients {
		recipients[i] = recipient
	}
	serialized := `{"protected":"` + newBuffer([]byte(`{"enc":"A128GCM"}`)).base64() +
		`","recipients":[` + strings.Join(recipients, ",") + `],"iv":"` + b64(12) +
		`","ciphertext":"` + b64(1) + `","tag":"` + b64(16) + `"}`

	obj, err := ParseEncryptedJSON(serialized,
		[]KeyAlgorithm{PBES2_HS256_A128KW}, []ContentEncryption{A128GCM})
	if err != nil {
		t.Fatalf("ParseEncryptedJSON: %v", err)
	}

	// Five maximum-cost recipients cannot fit a default budget that is twice
	// the per-recipient limit: two derivations run and the remaining three
	// are skipped, so the work is bounded by the budget rather than by the
	// number of recipients in the message.
	_, _, plaintext, err := obj.DecryptMulti("password")
	if !errors.Is(err, ErrPBES2WorkLimit) {
		t.Fatalf("DecryptMulti error = %v, want ErrPBES2WorkLimit", err)
	}
	if plaintext != nil {
		t.Fatalf("budget rejection returned %d bytes of plaintext", len(plaintext))
	}

	// With no budget at all, even the first derivation is refused, so a
	// message that would otherwise cost seconds returns immediately.
	withPBES2WorkLimit(t, 0, func() {
		if _, _, _, err := obj.DecryptMulti("password"); !errors.Is(err, ErrPBES2WorkLimit) {
			t.Fatalf("DecryptMulti with zero budget error = %v, want ErrPBES2WorkLimit", err)
		}
	})
}

// The default budget admits several recipients at the default iteration count:
// three recipients are within twice the per-recipient limit, and the last of
// them still decrypts. A fourth default-cost recipient would overrun it.
func TestDecryptMultiPBES2DefaultBudgetBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("derives PBKDF2 keys at the default iteration count")
	}

	passwords := []string{"first", "second", "third", "fourth"}
	recipients := make([]Recipient, len(passwords))
	for i, password := range passwords {
		// PBES2Count left at zero makes the encrypter use defaultP2C.
		recipients[i] = Recipient{Algorithm: PBES2_HS256_A128KW, Key: password}
	}

	three := encryptPBES2Multi(t, recipients[:3])
	index, _, plaintext, err := three.DecryptMulti(passwords[2])
	if err != nil {
		t.Fatalf("three default-cost recipients: DecryptMulti: %v", err)
	}
	if index != 2 || string(plaintext) != "Lorem ipsum dolor sit amet" {
		t.Fatalf("index = %d, plaintext = %q", index, plaintext)
	}

	four := encryptPBES2Multi(t, recipients)
	_, _, plaintext, err = four.DecryptMulti(passwords[3])
	if !errors.Is(err, ErrPBES2WorkLimit) {
		t.Fatalf("four default-cost recipients: error = %v, want ErrPBES2WorkLimit", err)
	}
	if plaintext != nil {
		t.Fatalf("budget rejection returned %d bytes of plaintext", len(plaintext))
	}

	// A budget large enough for all four lets the last recipient decrypt.
	withPBES2WorkLimit(t, 4*defaultP2C, func() {
		index, _, plaintext, err = four.DecryptMulti(passwords[3])
		if err != nil {
			t.Fatalf("raised budget: DecryptMulti: %v", err)
		}
		if index != 3 || string(plaintext) != "Lorem ipsum dolor sit amet" {
			t.Fatalf("raised budget: index = %d, plaintext = %q", index, plaintext)
		}
	})
}

// A zero budget refuses every derivation, which is how an application can
// disable PBES2 decryption entirely; the default value admits several
// default-cost recipients.
func TestPBES2WorkBudgetZeroAndDefault(t *testing.T) {
	if MaxPBES2Work != maxP2CPerMessage {
		t.Fatalf("default MaxPBES2Work = %d, want %d", MaxPBES2Work, maxP2CPerMessage)
	}

	symmetric := &symmetricKeyCipher{key: []byte("password")}
	header := rawHeader{}
	if err := header.set(headerAlgorithm, PBES2_HS256_A128KW); err != nil {
		t.Fatalf("setting alg: %v", err)
	}
	if err := header.set(headerP2S, newBuffer([]byte("salt"))); err != nil {
		t.Fatalf("setting p2s: %v", err)
	}
	if err := header.set(headerP2C, 1); err != nil {
		t.Fatalf("setting p2c: %v", err)
	}
	recipient := &recipientInfo{encryptedKey: bytes.Repeat([]byte{0x01}, 24)}

	withPBES2WorkLimit(t, 0, func() {
		budget := newPBES2WorkBudget()
		if budget.spend(symmetric, header, recipient) {
			t.Fatal("a zero budget must refuse every derivation")
		}
	})
}
