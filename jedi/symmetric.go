package jedi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// AESKeySize is the key size to use with AES, in bytes.
const AESKeySize = 16

func aesCTREncryptInMem(dst []byte, src []byte, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	iv := dst[:aes.BlockSize]
	if _, err = rand.Read(iv); err != nil {
		return err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(dst[aes.BlockSize:], src)
	return nil
}

func aesCTRDecryptInMem(dst []byte, src []byte, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	iv := src[:aes.BlockSize]
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(dst, src[aes.BlockSize:])
	return nil
}
