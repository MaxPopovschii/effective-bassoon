package main

import (
	"crypto/rand"
	"encoding/hex"
)

type SaltService struct{}

func (s *SaltService) Generate(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
