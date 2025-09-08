package main

import (
	"encoding/json"
	"net/http"
	"strconv"
)

func main() {
	crypto := &CryptoService{}
	hmacService := &HMACService{}
	passwordService := &PasswordService{}
	saltService := &SaltService{}
	jwtService := NewJWTService("supersecretkey")
	hashService := &HashService{}
	rsaService, _ := NewRSAService(2048)

	http.HandleFunc("/crypto", func(w http.ResponseWriter, r *http.Request) {
		algo := r.URL.Query().Get("algo")
		msg := r.URL.Query().Get("msg")
		action := r.URL.Query().Get("action") // "encode" (default) o "decode"
		key := r.URL.Query().Get("key")       // solo per AES
		var result string
		var err error

		switch algo {
		case "base64":
			if action == "decode" {
				result, err = crypto.DecodeBase64(msg)
				if err != nil {
					http.Error(w, "Invalid base64 string", http.StatusBadRequest)
					return
				}
			} else {
				result = crypto.EncodeBase64(msg)
			}
		case "md5":
			result = crypto.HashMD5(msg)
		case "sha256":
			result = crypto.HashSHA256(msg)
		case "aes":
			if key == "" {
				http.Error(w, "Missing key for AES", http.StatusBadRequest)
				return
			}
			if action == "decode" {
				result, err = crypto.DecryptAES(msg, key)
				if err != nil {
					http.Error(w, "AES decryption error: "+err.Error(), http.StatusBadRequest)
					return
				}
			} else {
				result, err = crypto.EncryptAES(msg, key)
				if err != nil {
					http.Error(w, "AES encryption error: "+err.Error(), http.StatusBadRequest)
					return
				}
			}
		default:
			http.Error(w, "Supported algorithms: base64, md5, sha256, aes", http.StatusBadRequest)
			return
		}

		resp := map[string]string{
			"algorithm": algo,
			"action":    action,
			"input":     msg,
			"output":    result,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/hmac", func(w http.ResponseWriter, r *http.Request) {
		msg := r.URL.Query().Get("msg")
		key := r.URL.Query().Get("key")
		if msg == "" || key == "" {
			http.Error(w, "Missing msg or key", http.StatusBadRequest)
			return
		}
		result := hmacService.ComputeSHA256(msg, key)
		resp := map[string]string{
			"algorithm": "hmac-sha256",
			"input":     msg,
			"key":       key,
			"output":    result,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/password", func(w http.ResponseWriter, r *http.Request) {
		lengthStr := r.URL.Query().Get("length")
		length, err := strconv.Atoi(lengthStr)
		if err != nil || length < 8 {
			length = 16
		}
		pass, err := passwordService.Generate(length)
		if err != nil {
			http.Error(w, "Password generation error", http.StatusInternalServerError)
			return
		}
		resp := map[string]string{"password": pass}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/salt", func(w http.ResponseWriter, r *http.Request) {
		lengthStr := r.URL.Query().Get("length")
		length, err := strconv.Atoi(lengthStr)
		if err != nil || length < 8 {
			length = 16
		}
		salt, err := saltService.Generate(length)
		if err != nil {
			http.Error(w, "Salt generation error", http.StatusInternalServerError)
			return
		}
		resp := map[string]string{"salt": salt}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/jwt/generate", func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		token, err := jwtService.Generate(username)
		if err != nil {
			http.Error(w, "JWT generation error", http.StatusInternalServerError)
			return
		}
		resp := map[string]string{"jwt": token}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/jwt/validate", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		claims, err := jwtService.Validate(token)
		if err != nil {
			http.Error(w, "JWT validation error", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(claims)
	})

	http.HandleFunc("/verify-hash", func(w http.ResponseWriter, r *http.Request) {
		algo := r.URL.Query().Get("algo")
		msg := r.URL.Query().Get("msg")
		hash := r.URL.Query().Get("hash")
		var valid bool

		switch algo {
		case "md5":
			valid = hashService.VerifyMD5(msg, hash, crypto)
		case "sha256":
			valid = hashService.VerifySHA256(msg, hash, crypto)
		default:
			http.Error(w, "Supported algorithms: md5, sha256", http.StatusBadRequest)
			return
		}

		resp := map[string]bool{"valid": valid}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/rsa/encrypt", func(w http.ResponseWriter, r *http.Request) {
		msg := r.URL.Query().Get("msg")
		result, err := rsaService.Encrypt(msg)
		if err != nil {
			http.Error(w, "RSA encryption error: "+err.Error(), http.StatusBadRequest)
			return
		}
		resp := map[string]string{"output": result}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/rsa/decrypt", func(w http.ResponseWriter, r *http.Request) {
		cipherText := r.URL.Query().Get("msg")
		result, err := rsaService.Decrypt(cipherText)
		if err != nil {
			http.Error(w, "RSA decryption error: "+err.Error(), http.StatusBadRequest)
			return
		}
		resp := map[string]string{"output": result}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/rsa/public", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{"public_key": rsaService.ExportPublicKeyPEM()}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	http.ListenAndServe(":80", nil)
}
