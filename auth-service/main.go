package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	accessTTL  = 15 * time.Minute
	refreshTTL = 24 * time.Hour
	issuer     = "auth-service"
	audience   = "api-service"
)

type user struct {
	hash []byte
	role string
}

type refreshEntry struct {
	username string
	expires  time.Time
}

type server struct {
	key       *rsa.PrivateKey
	users     map[string]user
	dummyHash []byte
	mu        sync.Mutex
	refresh   map[string]refreshEntry
}

func main() {
	key, err := loadKey(os.Getenv("JWT_PRIVATE_KEY_FILE"))
	if err != nil {
		log.Fatalf("private key: %v", err)
	}
	users, err := loadUsers(os.Getenv("AUTH_USERS"))
	if err != nil {
		log.Fatalf("users: %v", err)
	}
	dummy, _ := bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)
	s := &server{key: key, users: users, dummyHash: dummy, refresh: map[string]refreshEntry{}}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /refresh", s.refreshToken)

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	log.Println("auth-service listening on :8080")
	log.Fatal(srv.ListenAndServe())
}

func loadKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, nil
		}
		return nil, errors.New("not an RSA key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

// loadUsers parses "name:password:role,name:password:role" and bcrypt-hashes the passwords.
func loadUsers(spec string) (map[string]user, error) {
	users := map[string]user{}
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 3)
		if len(parts) != 3 {
			return nil, errors.New("AUTH_USERS entries must be name:password:role")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(parts[1]), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		users[parts[0]] = user{hash: hash, role: parts[2]}
	}
	if len(users) == 0 {
		return nil, errors.New("AUTH_USERS is empty")
	}
	return users, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	u, ok := s.users[req.Username]
	hash := u.hash
	if !ok {
		hash = s.dummyHash // compare anyway so unknown users cost the same time
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(req.Password)) != nil || !ok {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	s.issue(w, req.Username)
}

func (s *server) refreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	entry, ok := s.refresh[req.RefreshToken]
	delete(s.refresh, req.RefreshToken) // single use: rotated on every refresh
	s.mu.Unlock()
	if !ok || time.Now().After(entry.expires) {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}
	s.issue(w, entry.username)
}

func (s *server) issue(w http.ResponseWriter, username string) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":  issuer,
		"aud":  audience,
		"sub":  username,
		"role": s.users[username].role,
		"iat":  now.Unix(),
		"exp":  now.Add(accessTTL).Unix(),
	}
	access, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(s.key)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	refresh := base64.RawURLEncoding.EncodeToString(buf)
	s.mu.Lock()
	for k, v := range s.refresh { // drop expired entries
		if now.After(v.expires) {
			delete(s.refresh, k)
		}
	}
	s.refresh[refresh] = refreshEntry{username: username, expires: now.Add(refreshTTL)}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(tokenResponse{AccessToken: access, RefreshToken: refresh, ExpiresIn: int(accessTTL.Seconds())})
}
