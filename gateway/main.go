package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

func proxy(target string) http.Handler {
	u, err := url.Parse(target)
	if err != nil {
		log.Fatalf("bad upstream %q: %v", target, err)
	}
	return httputil.NewSingleHostReverseProxy(u)
}

func main() {
	authURL := getenv("AUTH_SERVICE_URL", "http://auth-service:8080")
	apiURL := getenv("API_SERVICE_URL", "http://api-service:8081")

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	// Only login and refresh are exposed from the auth-service.
	mux.Handle("POST /auth/login", http.StripPrefix("/auth", proxy(authURL)))
	mux.Handle("POST /auth/refresh", http.StripPrefix("/auth", proxy(authURL)))
	mux.Handle("/api/", http.StripPrefix("/api", proxy(apiURL)))

	srv := &http.Server{
		Addr:              ":8000",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	log.Println("gateway listening on :8000")
	log.Fatal(srv.ListenAndServe())
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
