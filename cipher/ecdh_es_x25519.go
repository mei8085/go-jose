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
	"crypto"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
)

// DeriveECDHESX25519 derives a shared encryption key using ECDH/ConcatKDF as
// described in JWE/JWA, with the X25519 function from RFC 7748 as profiled by
// RFC 8037.
//
// It is an error to call this function with keys that are not on the same
// curve; callers must ensure that the keys are valid before calling this
// function. In particular, priv must be an X25519 private key and pub must be
// the matching X25519 public key. Output size may be at most 1<<16 bytes
// (64 KiB).
func DeriveECDHESX25519(alg string, apuData, apvData []byte, priv *ecdh.PrivateKey, pub *ecdh.PublicKey, size int) ([]byte, error) {
	if size > 1<<16 {
		panic("ECDH-ES output size too large, must be less than or equal to 1<<16")
	}
	if priv == nil || pub == nil {
		return nil, errors.New("go-jose/go-jose: invalid X25519 key")
	}
	if priv.Curve() != ecdh.X25519() || pub.Curve() != ecdh.X25519() {
		return nil, errors.New("go-jose/go-jose: X25519 keys not on the same curve")
	}

	// RFC 7748 section 6.1: the shared secret is the raw X25519 output, i.e.
	// the 32-byte u-coordinate. Unlike the NIST curves it is neither padded nor
	// truncated, and crypto/ecdh additionally rejects low-order points.
	zBytes, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}

	// algId, partyUInfo, partyVInfo inputs must be prefixed with the length
	algID := lengthPrefixed([]byte(alg))
	ptyUInfo := lengthPrefixed(apuData)
	ptyVInfo := lengthPrefixed(apvData)

	// suppPubInfo is the encoded length of the output size in bits
	supPubInfo := make([]byte, 4)
	binary.BigEndian.PutUint32(supPubInfo, uint32(size)*8)

	reader := NewConcatKDF(crypto.SHA256, zBytes, algID, ptyUInfo, ptyVInfo, supPubInfo, []byte{})
	key := make([]byte, size)

	// Read on the KDF will never fail
	_, _ = reader.Read(key)

	return key, nil
}
