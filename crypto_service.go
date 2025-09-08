package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// CryptoService gestisce le operazioni di crittografia
type CryptoService struct{}

// EncodeBase64 codifica una stringa in base64
func (c *CryptoService) EncodeBase64(msg string) string {
	return base64.StdEncoding.EncodeToString([]byte(msg))
}

// DecodeBase64 decodifica una stringa base64
func (c *CryptoService) DecodeBase64(msg string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(msg)
	return string(decoded), err
}

// HashMD5 calcola l'hash MD5
func (c *CryptoService) HashMD5(msg string) string {
	hash := md5.Sum([]byte(msg))
	return hex.EncodeToString(hash[:])
}

// HashSHA256 calcola l'hash SHA256
func (c *CryptoService) HashSHA256(msg string) string {
	hash := sha256.Sum256([]byte(msg))
	return hex.EncodeToString(hash[:])
}

// EncryptAES cifra un messaggio con AES-256 e una chiave (32 byte)
func (c *CryptoService) EncryptAES(msg, key string) (string, error) {
	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		return "", errors.New("key must be 32 bytes for AES-256")
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	plaintext := []byte(msg)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES decifra un messaggio cifrato con AES-256 e una chiave (32 byte)
func (c *CryptoService) DecryptAES(cipherTextB64, key string) (string, error) {
	keyBytes := []byte(key)
	if len(keyBytes) != 32 {
		return "", errors.New("key must be 32 bytes for AES-256")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(cipherTextB64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext), nil
}
