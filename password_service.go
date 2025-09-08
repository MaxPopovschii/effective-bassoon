package main

import (
	"crypto/rand"
	"encoding/base64"
)

type PasswordService struct{}

func (p *PasswordService) Generate(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes)[:length], nil
}
