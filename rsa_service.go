package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

type RSAService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewRSAService(bits int) (*RSAService, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &RSAService{privateKey: priv, publicKey: &priv.PublicKey}, nil
}

func (r *RSAService) Encrypt(msg string) (string, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, []byte(msg))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (r *RSAService) Decrypt(cipherTextB64 string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(cipherTextB64)
	if err != nil {
		return "", err
	}
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (r *RSAService) ExportPublicKeyPEM() string {
	pubASN1 := x509.MarshalPKCS1PublicKey(r.publicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	return string(pubPEM)
}
