package db

import (
	"database/sql"
	"embed"
	"fmt"
	"strings"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var files embed.FS

func Open(path string) (*sql.DB, error) {
	if path == ":memory:" {
		path = "file::memory:?cache=shared"
	}
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}
	database, err := sql.Open("sqlite", path+separator+"_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	if err = database.Ping(); err != nil {
		return nil, err
	}
	schema, err := files.ReadFile("schema.sql")
	if err != nil {
		return nil, err
	}
	for _, statement := range strings.Split(string(schema), ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err = database.Exec(statement); err != nil {
			return nil, fmt.Errorf("migration: %w", err)
		}
	}
	if err := ensureColumn(database, "users", "must_change_password", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return nil, err
	}
	if err := ensureColumn(database, "organizations", "status", "TEXT NOT NULL DEFAULT 'active'"); err != nil {
		return nil, err
	}
	if err := ensureColumn(database, "users", "uuid", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return nil, err
	}
	if err := ensureColumn(database, "devices", "mac_address", "TEXT"); err != nil {
		return nil, err
	}
	if err := ensureColumn(database, "devices", "api_key", "TEXT"); err != nil {
		return nil, err
	}
	// Device credentials are stored only as hashes. Clear any legacy plaintext
	// values left by older builds; the API key is shown only at provisioning time.
	if _, err := database.Exec("UPDATE devices SET api_key='' WHERE api_key IS NOT NULL AND api_key != ''"); err != nil {
		return nil, err
	}
	if err := ensureColumn(database, "devices", "last_seen_at", "TEXT"); err != nil {
		return nil, err
	}
	if err := ensureColumn(database, "attendance_events", "event_id", "TEXT"); err != nil {
		return nil, err
	}
	if _, err := database.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS attendance_events_event_id_idx ON attendance_events(event_id) WHERE event_id IS NOT NULL AND event_id != ''`); err != nil {
		return nil, err
	}
	if err := ensureColumn(database, "rfid_cards", "card_uid", "TEXT"); err != nil {
		return nil, err
	}
	if err := ensureColumn(database, "rfid_cards", "card_type", "TEXT NOT NULL DEFAULT 'standard'"); err != nil {
		return nil, err
	}
	if _, err := database.Exec(`CREATE TABLE IF NOT EXISTS pending_device_enrollments (
		id VARCHAR(36) PRIMARY KEY,
		org_id VARCHAR(36) NOT NULL,
		mac_address VARCHAR(17) UNIQUE NOT NULL,
		device_name VARCHAR(100) NOT NULL,
		location VARCHAR(100),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return nil, err
	}
	if err := backfillUserUUIDs(database); err != nil {
		return nil, err
	}
	if _, err := database.Exec("CREATE UNIQUE INDEX IF NOT EXISTS users_uuid ON users(uuid)"); err != nil {
		return nil, err
	}
	if _, err := database.Exec("CREATE UNIQUE INDEX IF NOT EXISTS devices_mac ON devices(mac_address) WHERE mac_address IS NOT NULL AND mac_address != ''"); err != nil {
		return nil, err
	}
	return database, nil
}

func backfillUserUUIDs(database *sql.DB) error {
	rows, err := database.Query("SELECT id FROM users WHERE uuid IS NULL OR uuid=''")
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	for _, id := range ids {
		if _, err := database.Exec("UPDATE users SET uuid=? WHERE id=?", uuid.NewString(), id); err != nil {
			return err
		}
	}
	return nil
}

func ensureColumn(database *sql.DB, table, column, definition string) error {
	rows, err := database.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	_, err = database.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition)
	return err
}
