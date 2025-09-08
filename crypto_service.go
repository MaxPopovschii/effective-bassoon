package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
