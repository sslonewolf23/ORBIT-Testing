package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

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
	recoveryPepper string
	awsRegion string
	anchorTable string
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
		recoveryPepper: strings.TrimSpace(os.Getenv("ORBIT_RECOVERY_PEPPER")),
		awsRegion: strings.TrimSpace(os.Getenv("AWS_REGION")),
		anchorTable: strings.TrimSpace(os.Getenv("ORBIT_ANCHOR_TABLE")),
	}
	if c.appID == "" || c.rootPEM == "" || c.dbPath == "" ||
		c.tlsCert == "" || c.tlsKey == "" || c.recoveryPepper == "" || c.awsRegion == "" || c.anchorTable == "" {
		return c, errors.New("ORBIT_APP_ID, ORBIT_APP_ATTEST_ROOT_PEM, ORBIT_DB_PATH, ORBIT_TLS_CERT, ORBIT_TLS_KEY, ORBIT_RECOVERY_PEPPER, AWS_REGION and ORBIT_ANCHOR_TABLE are required")
	}
	appParts := strings.SplitN(c.appID, ".", 2)
	if len(appParts) != 2 || len(appParts[0]) != 10 || appParts[1] == "" ||
		strings.TrimSpace(c.appID) != c.appID || len(c.appID) > 255 {
		return c, errors.New("ORBIT_APP_ID must be the exact 10-character Team ID followed by a bundle identifier")
	}
	if len(c.recoveryPepper) < 32 { return c, errors.New("ORBIT_RECOVERY_PEPPER must contain at least 32 characters of random secret material") }
	if !filepath.IsAbs(c.dbPath) {
		return c, errors.New("ORBIT_DB_PATH must be an absolute path")
	}
	if c.environment != "development" && c.environment != "production" {
		return c, errors.New("ORBIT_APP_ATTEST_ENV must be development or production")
	}
	if c.listen == "" { c.listen = "127.0.0.1:8443" }
	return c, nil
}

func openDatabase(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { return nil, err }
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil { return nil, err }
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("database path must be a regular file, not a symlink")
		}
		if err := os.Chmod(path, 0600); err != nil { return nil, err }
	} else if !os.IsNotExist(err) { return nil, err }
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
  created_at INTEGER NOT NULL,
  recovery_verifier BLOB
);
CREATE TABLE IF NOT EXISTS recovery_challenges (
  digest BLOB PRIMARY KEY NOT NULL,
  old_key_id TEXT NOT NULL,
  new_key_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS key_recovery_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  old_key_id TEXT NOT NULL,
  new_key_id TEXT NOT NULL UNIQUE,
  recovered_at INTEGER NOT NULL,
  prior_revision BLOB NOT NULL,
  prior_head_digest BLOB NOT NULL,
  prior_tombstone INTEGER NOT NULL
);
CREATE TRIGGER IF NOT EXISTS key_recovery_history_no_update
BEFORE UPDATE ON key_recovery_history BEGIN SELECT RAISE(ABORT, 'recovery history is immutable'); END;
CREATE TRIGGER IF NOT EXISTS key_recovery_history_no_delete
BEFORE DELETE ON key_recovery_history BEGIN SELECT RAISE(ABORT, 'recovery history is immutable'); END;`
	if _, err = db.Exec(schema); err != nil { db.Close(); return nil, err }
	if err = ensureRecoveryVerifierColumn(db); err != nil { db.Close(); return nil, err }
	if err = ensureAnchorSequenceColumn(db); err != nil { db.Close(); return nil, err }
	if _, err = db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS installations_recovery_verifier_unique ON installations(recovery_verifier) WHERE recovery_verifier IS NOT NULL"); err != nil { db.Close(); return nil, err }
	if err = os.Chmod(path, 0600); err != nil { db.Close(); return nil, err }
	return db, nil
}

func ensureAnchorSequenceColumn(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(installations)")
	if err != nil { return err }
	found := false
	for rows.Next() {
		var cid, notNull, primary int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary); err != nil { rows.Close(); return err }
		if name == "anchor_sequence" { found = true }
	}
	if err := rows.Err(); err != nil { rows.Close(); return err }
	if err := rows.Close(); err != nil { return err }
	if found { return nil }
	_, err = db.Exec("ALTER TABLE installations ADD COLUMN anchor_sequence INTEGER NOT NULL DEFAULT 0")
	return err
}

func ensureRecoveryVerifierColumn(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(installations)")
	if err != nil { return err }
	found := false
	for rows.Next() {
		var cid, notNull, primary int
		var name, kind string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primary); err != nil {
			rows.Close()
			return err
		}
		if name == "recovery_verifier" { found = true }
	}
	if err := rows.Err(); err != nil { rows.Close(); return err }
	if err := rows.Close(); err != nil { return err }
	if found { return nil }
	_, err = db.Exec("ALTER TABLE installations ADD COLUMN recovery_verifier BLOB")
	return err
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

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithRegion(cfg.awsRegion))
	if err != nil { log.Fatal(err) }
	anchor, err := newDynamoAnchor(dynamodb.NewFromConfig(awsCfg), cfg.anchorTable)
	if err != nil { log.Fatal(err) }
	anchorCtx, cancelAnchorCheck := context.WithTimeout(context.Background(),5*time.Second)
	if err := anchor.Health(anchorCtx); err != nil {
		cancelAnchorCheck()
		log.Fatalf("independent monotonic anchor unavailable: %v",err)
	}
	cancelAnchorCheck()
	s := &service{db: db, appID: cfg.appID, environment: cfg.environment,
		roots: roots, now: time.Now, recoveryPepper: []byte(cfg.recoveryPepper), anchor: anchor}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := db.Ping(); err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := anchor.Health(r.Context()); err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /v1/orbit/journal/attestation-challenge", s.challenge)
	mux.HandleFunc("POST /v1/orbit/journal/register", s.register)
	mux.HandleFunc("POST /v1/orbit/journal/recovery-challenge", s.recoveryChallenge)
	mux.HandleFunc("POST /v1/orbit/journal/recover", s.recoverKey)
	mux.HandleFunc("POST /v1/orbit/journal/head", s.head)
	mux.HandleFunc("POST /v1/orbit/journal/compare-and-swap", s.compareAndSwap)
	server := &http.Server{Addr: cfg.listen, Handler: securityHeaders(mux),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
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
