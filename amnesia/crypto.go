package amnezia

import (
	"bytes"
	"crypto/aes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

type encryptedEnvelope struct {
	body      []byte
	key       []byte
	iv        []byte
	salt      []byte
	requestID string
}

func parseRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if parsed, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		key, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("PEM key is not RSA")
		}
		return key, nil
	}
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA public key: %w", err)
	}
	return key, nil
}

func prepareEnvelope(random io.Reader, publicKey *rsa.PublicKey, payload any, requestID string) (*encryptedEnvelope, error) {
	key := make([]byte, 32)
	iv := make([]byte, 32)
	salt := make([]byte, 8)
	for _, target := range [][]byte{key, iv, salt} {
		if _, err := io.ReadFull(random, target); err != nil {
			return nil, fmt.Errorf("random data: %w", err)
		}
	}

	keyPayload, err := json.Marshal(map[string]string{
		"aes_key":  base64.StdEncoding.EncodeToString(key),
		"aes_iv":   base64.StdEncoding.EncodeToString(iv),
		"aes_salt": base64.StdEncoding.EncodeToString(salt),
	})
	if err != nil {
		return nil, err
	}
	encryptedKey, err := rsa.EncryptPKCS1v15(random, publicKey, keyPayload)
	if err != nil {
		return nil, fmt.Errorf("RSA encrypt key payload: %w", err)
	}
	apiPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal API payload: %w", err)
	}
	encryptedAPI, err := encryptAES256CBC(apiPayload, key, iv)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(map[string]string{
		"key_payload": base64.StdEncoding.EncodeToString(encryptedKey),
		"api_payload": base64.StdEncoding.EncodeToString(encryptedAPI),
	})
	if err != nil {
		return nil, err
	}
	return &encryptedEnvelope{body: body, key: key, iv: iv, salt: salt, requestID: requestID}, nil
}

func encryptAES256CBC(plain, key, iv []byte) ([]byte, error) {
	if len(key) != 32 || len(iv) < aes.BlockSize {
		return nil, errors.New("invalid AES-256-CBC key or IV length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plain, aes.BlockSize)
	out := make([]byte, len(padded))
	cbcEncrypt(block, out, padded, iv[:aes.BlockSize])
	return out, nil
}

func decryptAES256CBC(ciphertext, key, iv []byte) ([]byte, error) {
	if len(key) != 32 || len(iv) < aes.BlockSize {
		return nil, errors.New("invalid AES-256-CBC key or IV length")
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("invalid AES-CBC ciphertext length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	cbcDecrypt(block, out, ciphertext, iv[:aes.BlockSize])
	return pkcs7Unpad(out, aes.BlockSize)
}

// These small loops keep crypto.go dependency-free while delegating each block
// operation to the constant-time standard-library AES implementation.
func cbcEncrypt(block interface {
	Encrypt(dst, src []byte)
	BlockSize() int
}, dst, src, iv []byte) {
	previous := append([]byte(nil), iv...)
	for len(src) > 0 {
		for i := range previous {
			dst[i] = src[i] ^ previous[i]
		}
		block.Encrypt(dst[:block.BlockSize()], dst[:block.BlockSize()])
		copy(previous, dst[:block.BlockSize()])
		src = src[block.BlockSize():]
		dst = dst[block.BlockSize():]
	}
}

func cbcDecrypt(block interface {
	Decrypt(dst, src []byte)
	BlockSize() int
}, dst, src, iv []byte) {
	previous := append([]byte(nil), iv...)
	for len(src) > 0 {
		current := append([]byte(nil), src[:block.BlockSize()]...)
		block.Decrypt(dst[:block.BlockSize()], src[:block.BlockSize()])
		for i := range previous {
			dst[i] ^= previous[i]
		}
		copy(previous, current)
		src = src[block.BlockSize():]
		dst = dst[block.BlockSize():]
	}
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	return append(append([]byte(nil), data...), bytes.Repeat([]byte{byte(padding)}, padding)...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid PKCS#7 length")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > blockSize || padding > len(data) {
		return nil, errors.New("invalid PKCS#7 padding")
	}
	for _, b := range data[len(data)-padding:] {
		if int(b) != padding {
			return nil, errors.New("invalid PKCS#7 padding")
		}
	}
	return data[:len(data)-padding], nil
}
