package main

type HashService struct{}

func (h *HashService) VerifyMD5(msg, hash string, crypto *CryptoService) bool {
	return crypto.HashMD5(msg) == hash
}

func (h *HashService) VerifySHA256(msg, hash string, crypto *CryptoService) bool {
	return crypto.HashSHA256(msg) == hash
}
