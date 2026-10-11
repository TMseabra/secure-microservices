package main

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func token(t *testing.T, key *rsa.PrivateKey, method jwt.SigningMethod, mc jwt.MapClaims) string {
	t.Helper()
	var k any = key
	if method == jwt.SigningMethodNone {
		k = jwt.UnsafeAllowNoneSignatureType
	}
	s, err := jwt.NewWithClaims(method, mc).SignedString(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAuthorize(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	exp := time.Now().Add(time.Minute).Unix()
	good := func(role string) jwt.MapClaims {
		return jwt.MapClaims{"iss": "auth-service", "aud": "api-service", "sub": "u", "role": role, "exp": exp}
	}
	expired := good("admin")
	expired["exp"] = time.Now().Add(-time.Minute).Unix()
	wrongAud := good("admin")
	wrongAud["aud"] = "other"

	h := authorize(&key.PublicKey, "admin")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	cases := []struct {
		name string
		tok  string
		want int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"admin ok", token(t, key, jwt.SigningMethodRS256, good("admin")), http.StatusOK},
		{"user forbidden", token(t, key, jwt.SigningMethodRS256, good("user")), http.StatusForbidden},
		{"expired", token(t, key, jwt.SigningMethodRS256, expired), http.StatusUnauthorized},
		{"wrong audience", token(t, key, jwt.SigningMethodRS256, wrongAud), http.StatusUnauthorized},
		{"wrong key", token(t, other, jwt.SigningMethodRS256, good("admin")), http.StatusUnauthorized},
		{"alg none", token(t, key, jwt.SigningMethodNone, good("admin")), http.StatusUnauthorized},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		if c.tok != "" {
			req.Header.Set("Authorization", "Bearer "+c.tok)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: got %d, want %d", c.name, rec.Code, c.want)
		}
	}
}
