package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoverySchemaMigratesFreshAndLegacyDatabases(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "fresh"
		if legacy { name = "legacy" }
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "witness.sqlite")
			if legacy {
				db, err := sql.Open("sqlite", path)
				if err != nil { t.Fatal(err) }
				_, err = db.Exec(`CREATE TABLE installations (
					key_id TEXT PRIMARY KEY NOT NULL,
					public_key BLOB NOT NULL,
					attestation_digest BLOB NOT NULL,
					assertion_counter INTEGER NOT NULL DEFAULT 0,
					revision BLOB NOT NULL,
					head_digest BLOB NOT NULL,
					tombstone INTEGER NOT NULL,
					created_at INTEGER NOT NULL
				);`)
				if err != nil { t.Fatal(err) }
				if err := db.Close(); err != nil { t.Fatal(err) }
			}

			db, err := openDatabase(path)
			if err != nil { t.Fatal(err) }
			defer db.Close()
			rows, err := db.Query("PRAGMA table_info(installations)")
			if err != nil { t.Fatal(err) }
			found := false
			for rows.Next() {
				var cid int
				var column, kind string
				var notNull, primary int
				var defaultValue any
				if err := rows.Scan(&cid, &column, &kind, &notNull, &defaultValue, &primary); err != nil {
					t.Fatal(err)
				}
				if column == "recovery_verifier" { found = true }
			}
			if err := rows.Err(); err != nil { t.Fatal(err) }
			_ = rows.Close()
			if !found { t.Fatal("recovery_verifier column missing after migration") }

			var triggerCount int
			if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN (?,?)",
				"key_recovery_history_no_update", "key_recovery_history_no_delete").Scan(&triggerCount); err != nil {
				t.Fatal(err)
			}
			if triggerCount != 2 { t.Fatalf("immutable recovery history triggers = %d, want 2", triggerCount) }
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("database permissions not private: %v", err)
			}
		})
	}
}
