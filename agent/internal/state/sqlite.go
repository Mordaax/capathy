// Package state persists unique run claims and append-only audit decisions.
package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

// Store owns a SQLite connection pool.
type Store struct{ db *sql.DB }

// AuditEvent deliberately contains hashes and decisions, never raw samples or credentials.
type AuditEvent struct {
	Kind   string    `json:"kind"`
	Digest string    `json:"digest,omitempty"`
	At     time.Time `json:"at"`
}

// Open creates or migrates a local state database with private file permissions.
func Open(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA busy_timeout=5000; PRAGMA user_version=1; CREATE TABLE IF NOT EXISTS runs (key TEXT PRIMARY KEY, created TEXT NOT NULL); CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY AUTOINCREMENT, run_key TEXT NOT NULL, event TEXT NOT NULL)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate state: %w", err)
	}
	return &Store{db}, nil
}

// Close releases the store's database connections.
func (s *Store) Close() error { return s.db.Close() }

// Claim atomically admits one worker for a durable idempotency key.
func (s *Store) Claim(ctx context.Context, key string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO runs(key,created) VALUES (?,?)", key, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 1 {
		event, _ := json.Marshal(AuditEvent{Kind: "claimed", At: time.Now().UTC()})
		if _, err = tx.ExecContext(ctx, "INSERT INTO audit(run_key,event) VALUES (?,?)", key, string(event)); err != nil {
			return false, err
		}
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return n == 1, nil
}

// Record appends one bounded audit event for an existing run.
func (s *Store) Record(ctx context.Context, key string, event AuditEvent) error {
	if len(event.Kind) > 128 || len(event.Digest) > 128 {
		return fmt.Errorf("audit event too large")
	}
	event.At = time.Now().UTC()
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, "INSERT INTO audit(run_key,event) SELECT key,? FROM runs WHERE key=?", string(b), key)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("run not claimed")
	}
	return nil
}

// Get reads the ordered audit trail for one run.
func (s *Store) Get(ctx context.Context, key string) ([]AuditEvent, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT event FROM audit WHERE run_key=? ORDER BY seq", key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := []AuditEvent{}
	for rows.Next() {
		var text string
		if err = rows.Scan(&text); err != nil {
			return nil, err
		}
		var event AuditEvent
		if err = json.Unmarshal([]byte(text), &event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}
