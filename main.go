package main

import (
	"encoding/json"
	"net/http"
)

func main() {
	crypto := &CryptoService{}

	http.HandleFunc("/crypto", func(w http.ResponseWriter, r *http.Request) {
		algo := r.URL.Query().Get("algo")
		msg := r.URL.Query().Get("msg")
		action := r.URL.Query().Get("action") // "encode" (default) o "decode"
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
		default:
			http.Error(w, "Supported algorithms: base64, md5, sha256", http.StatusBadRequest)
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

	http.ListenAndServe(":80", nil)
}
