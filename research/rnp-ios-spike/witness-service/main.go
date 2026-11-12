package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type config struct {
	appID      string
	environment string
	rootPEM    string
	dbPath     string
	listen     string
	tlsCert    string
	tlsKey     string
}

func loadConfig() (config, error) {
	c := config{
		appID: strings.TrimSpace(os.Getenv("ORBIT_APP_ID")),
		environment: strings.TrimSpace(os.Getenv("ORBIT_APP_ATTEST_ENV")),
		rootPEM: strings.TrimSpace(os.Getenv("ORBIT_APP_ATTEST_ROOT_PEM")),
		dbPath: strings.TrimSpace(os.Getenv("ORBIT_DB_PATH")),
		listen: strings.TrimSpace(os.Getenv("ORBIT_LISTEN")),
		tlsCert: strings.TrimSpace(os.Getenv("ORBIT_TLS_CERT")),
		tlsKey: strings.TrimSpace(os.Getenv("ORBIT_TLS_KEY")),
	}
	if c.appID == "" || c.rootPEM == "" || c.dbPath == "" ||
		c.tlsCert == "" || c.tlsKey == "" {
		return c, errors.New("ORBIT_APP_ID, ORBIT_APP_ATTEST_ROOT_PEM, ORBIT_DB_PATH, ORBIT_TLS_CERT and ORBIT_TLS_KEY are required")
	}
	if c.environment != "development" && c.environment != "production" {
		return c, errors.New("ORBIT_APP_ATTEST_ENV must be development or production")
	}
	if c.listen == "" { c.listen = "127.0.0.1:8443" }
	return c, nil
}

func openDatabase(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil { return nil, err }
	db.SetMaxOpenConns(1)
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	}
	for _, q := range pragmas {
		if _, err = db.Exec(q); err != nil { db.Close(); return nil, err }
	}
	schema := `
CREATE TABLE IF NOT EXISTS challenges (
  digest BLOB PRIMARY KEY NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS installations (
  key_id TEXT PRIMARY KEY NOT NULL,
  public_key BLOB NOT NULL,
  attestation_digest BLOB NOT NULL,
  assertion_counter INTEGER NOT NULL DEFAULT 0,
  revision BLOB NOT NULL,
  head_digest BLOB NOT NULL,
  tombstone INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);`
	if _, err = db.Exec(schema); err != nil { db.Close(); return nil, err }
	return db, nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil { return nil, err }
	pool := x509.NewCertPool()
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil { break }
		data = rest
		if block.Type != "CERTIFICATE" { continue }
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil { return nil, parseErr }
		pool.AddCert(cert)
	}
	if len(pool.Subjects()) == 0 { return nil, errors.New("no App Attest root certificates loaded") }
	return pool, nil
}

func main() {
	cfg, err := loadConfig()
	if err != nil { log.Fatal(err) }
	roots, err := loadRoots(cfg.rootPEM)
	if err != nil { log.Fatal(err) }
	db, err := openDatabase(cfg.dbPath)
	if err != nil { log.Fatal(err) }
	defer db.Close()

	s := &service{db: db, appID: cfg.appID, environment: cfg.environment,
		roots: roots, now: time.Now}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/orbit/journal/attestation-challenge", s.challenge)
	mux.HandleFunc("POST /v1/orbit/journal/register", s.register)
	mux.HandleFunc("POST /v1/orbit/journal/head", s.head)
	mux.HandleFunc("POST /v1/orbit/journal/compare-and-swap", s.compareAndSwap)
	server := &http.Server{Addr: cfg.listen, Handler: securityHeaders(mux),
		ReadHeaderTimeout: 5*time.Second, ReadTimeout: 10*time.Second,
		WriteTimeout: 15*time.Second, IdleTimeout: 30*time.Second,
		MaxHeaderBytes: 16<<10}
	log.Printf("ORBIT witness listening with TLS on %s", cfg.listen)
	if err := server.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
