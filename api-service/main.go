package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ctxKey struct{}

type claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func main() {
	pub, err := loadPublicKey(os.Getenv("JWT_PUBLIC_KEY_FILE"))
	if err != nil {
		log.Fatalf("public key: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.Handle("GET /items", authorize(pub, "user", "admin")(http.HandlerFunc(listItems)))
	mux.Handle("POST /items", authorize(pub, "admin")(http.HandlerFunc(createItem)))

	srv := &http.Server{
		Addr:              ":8081",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	log.Println("api-service listening on :8081")
	log.Fatal(srv.ListenAndServe())
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return rk, nil
}

// authorize validates the bearer JWT (RS256 only) and requires its role to be one of allowed.
func authorize(pub *rsa.PublicKey, allowed ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok {
				http.Error(w, "missing token", http.StatusUnauthorized)
				return
			}
			c := &claims{}
			_, err := jwt.ParseWithClaims(raw, c, func(*jwt.Token) (any, error) { return pub, nil },
				jwt.WithValidMethods([]string{"RS256"}),
				jwt.WithIssuer("auth-service"),
				jwt.WithAudience("api-service"),
				jwt.WithExpirationRequired(),
			)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			for _, role := range allowed {
				if c.Role == role {
					next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, c)))
					return
				}
			}
			http.Error(w, "forbidden", http.StatusForbidden)
		})
	}
}

func listItems(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value(ctxKey{}).(*claims)
	writeJSON(w, http.StatusOK, map[string]any{"user": c.Subject, "items": []string{"item-1", "item-2"}})
}

func createItem(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value(ctxKey{}).(*claims)
	writeJSON(w, http.StatusCreated, map[string]any{"created_by": c.Subject})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
