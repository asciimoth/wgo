/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	NoisePublicKeySize    = 32
	NoisePrivateKeySize   = 32
	NoisePresharedKeySize = 32
)

type (
	NoisePublicKey    [NoisePublicKeySize]byte
	NoisePrivateKey   [NoisePrivateKeySize]byte
	NoisePresharedKey [NoisePresharedKeySize]byte
	NoiseNonce        uint64 // padded to 12-bytes
)

// GeneratePrivateKey returns a new Curve25519 private key suitable for
// WireGuard static identity use.
func GeneratePrivateKey() (NoisePrivateKey, error) {
	return newPrivateKey()
}

// ParsePrivateKey parses a standard WireGuard base64 private key. Hex input is
// also accepted for compatibility with the lower-level FromHex API. An empty
// string returns the zero private key.
func ParsePrivateKey(value string) (NoisePrivateKey, error) {
	var key NoisePrivateKey
	if value == "" {
		return key, nil
	}
	if err := parseNoiseKey(key[:], value); err != nil {
		return NoisePrivateKey{}, err
	}
	key.clamp()
	return key, nil
}

// ParsePublicKey parses a standard WireGuard base64 public key. Hex input is
// also accepted for compatibility with the lower-level FromHex API. Empty and
// all-zero public keys are rejected.
func ParsePublicKey(value string) (NoisePublicKey, error) {
	var key NoisePublicKey
	if value == "" {
		return key, errors.New("empty public key")
	}
	if err := parseNoiseKey(key[:], value); err != nil {
		return NoisePublicKey{}, err
	}
	if key.IsZero() {
		return NoisePublicKey{}, errors.New("zero public key")
	}
	return key, nil
}

// ParsePresharedKey parses a standard WireGuard base64 preshared key. Hex
// input is also accepted for compatibility with the lower-level FromHex API. An
// empty string returns the zero preshared key.
func ParsePresharedKey(value string) (NoisePresharedKey, error) {
	var key NoisePresharedKey
	if value == "" {
		return key, nil
	}
	if err := parseNoiseKey(key[:], value); err != nil {
		return NoisePresharedKey{}, err
	}
	return key, nil
}

func parseNoiseKey(dst []byte, value string) error {
	if len(value) == hex.EncodedLen(len(dst)) {
		if err := loadExactHex(dst, value); err == nil {
			return nil
		}
	}
	if err := loadExactBase64(dst, value, base64.StdEncoding); err == nil {
		return nil
	}
	if err := loadExactBase64(dst, value, base64.RawStdEncoding); err == nil {
		return nil
	}
	return fmt.Errorf("invalid key encoding")
}

func loadExactBase64(dst []byte, src string, enc *base64.Encoding) error {
	slice, err := enc.DecodeString(src)
	if err != nil {
		return err
	}
	if len(slice) != len(dst) {
		return errors.New("base64 string does not fit the slice")
	}
	copy(dst, slice)
	return nil
}

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	if len(slice) != len(dst) {
		return errors.New("hex string does not fit the slice")
	}
	copy(dst, slice)
	return nil
}

func (key NoisePrivateKey) IsZero() bool {
	var zero NoisePrivateKey
	return key.Equals(zero)
}

func (key NoisePrivateKey) Equals(tar NoisePrivateKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key NoisePrivateKey) PublicKey() NoisePublicKey {
	return (&key).publicKey()
}

func (key NoisePrivateKey) Base64() string {
	return base64.StdEncoding.EncodeToString(key[:])
}

func (key *NoisePrivateKey) FromHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	key.clamp()
	return
}

func (key *NoisePrivateKey) FromMaybeZeroHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	if key.IsZero() {
		return
	}
	key.clamp()
	return
}

func (key *NoisePublicKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key NoisePublicKey) IsZero() bool {
	var zero NoisePublicKey
	return key.Equals(zero)
}

func (key NoisePublicKey) Equals(tar NoisePublicKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key NoisePublicKey) Base64() string {
	return base64.StdEncoding.EncodeToString(key[:])
}

func (key *NoisePresharedKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key NoisePresharedKey) Base64() string {
	return base64.StdEncoding.EncodeToString(key[:])
}
