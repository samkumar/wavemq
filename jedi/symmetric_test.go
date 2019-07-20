package jedi

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"testing"
)

func TestAESCTR(t *testing.T) {
	message := make([]byte, 1029)
	key := make([]byte, AESKeySize)

	if _, err := rand.Read(message); err != nil {
		panic(err)
	}

	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	encrypted := make([]byte, len(message)+aes.BlockSize)
	if err := aesCTREncryptInMem(encrypted, message, key); err != nil {
		panic(err)
	}

	decrypted := make([]byte, len(encrypted)-aes.BlockSize)
	if err := aesCTRDecryptInMem(decrypted, encrypted, key); err != nil {
		panic(err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Fatal("Original and decrypted messages differ")
	}
}
