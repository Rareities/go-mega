package mega

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"
)

func TestDecryptAttrRejectsMalformedCiphertext(t *testing.T) {
	_, err := decryptAttr(make([]byte, 16), base64urlencode([]byte("short")))
	if !errors.Is(err, EBADATTR) {
		t.Fatalf("decryptAttr() error=%v, want EBADATTR", err)
	}
}

func TestDecryptAttrRejectsMissingPrefixAndName(t *testing.T) {
	key := make([]byte, 16)
	for _, plaintext := range [][]byte{
		[]byte("NOPE{\"n\":\"name\"}"),
		[]byte("MEGA{}"),
	} {
		_, err := decryptAttr(key, encryptAttrPayload(t, key, plaintext))
		if !errors.Is(err, EBADATTR) {
			t.Errorf("decryptAttr(%q) error=%v, want EBADATTR", plaintext, err)
		}
	}
}

func TestDecryptAttrAcceptsValidEncryptedName(t *testing.T) {
	key := make([]byte, 16)
	encoded, err := encryptAttr(key, FileAttr{Name: "valid.txt"})
	if err != nil {
		t.Fatal(err)
	}
	attr, err := decryptAttr(key, encoded)
	if err != nil {
		t.Fatalf("decryptAttr() error=%v", err)
	}
	if attr.Name != "valid.txt" {
		t.Fatalf("attribute name=%q, want valid.txt", attr.Name)
	}
}

func encryptAttrPayload(t *testing.T, key, plaintext []byte) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	paddedLength := (len(plaintext) + block.BlockSize() - 1) / block.BlockSize() * block.BlockSize()
	padded := make([]byte, paddedLength)
	copy(padded, plaintext)
	ciphertext := make([]byte, len(padded))
	iv := make([]byte, block.BlockSize())
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return base64urlencode(ciphertext)
}
