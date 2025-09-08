package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

type HMACService struct{}

func (h *HMACService) ComputeSHA256(msg, key string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}
