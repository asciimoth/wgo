package amnezia

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestAES256CBCRoundTripAndPaddingValidation(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	iv := bytes.Repeat([]byte{0x24}, 32)
	plain := []byte("not block aligned")
	ciphertext, err := encryptAES256CBC(plain, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptAES256CBC(ciphertext, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip = %q, want %q", got, plain)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	if _, err := decryptAES256CBC(ciphertext, key, iv); err == nil {
		t.Fatal("corrupt PKCS#7 padding was accepted")
	}

	tagged, err := BuildTaggedPayload("<b 0x0102><r 4>", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(tagged) != 6 || tagged[0] != 1 || tagged[1] != 2 {
		t.Fatalf("tagged payload = %x", tagged)
	}
}
