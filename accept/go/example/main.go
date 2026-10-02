// The net/http example: GET /sigelo/challenge?did=…, POST /sigelo/login { challenge, did, sig, bundle }.
package main

import (
	"encoding/json"
	"net/http"
	"os"

	accept "sigelo-accept"
)

func main() {
	http.HandleFunc("GET /sigelo/challenge", func(w http.ResponseWriter, r *http.Request) {
		w.Write(accept.Challenge(r.URL.Query().Get("did"), "example.com"))
	})
	http.HandleFunc("POST /sigelo/login", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Challenge, Bundle json.RawMessage
			DID, Sig          string
		}
		json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&in)
		if res, err := accept.Accept(in.Challenge, in.DID, in.Sig, in.Bundle); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		} else {
			json.NewEncoder(w).Encode(map[string]string{"did": res.DID}) // put res.DID in your session
		}
	})
	http.ListenAndServe("127.0.0.1:"+os.Getenv("PORT"), nil)
}
