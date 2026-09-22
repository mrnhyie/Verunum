package db

import "testing"

func TestMigrationsCreateDatabase(t *testing.T) {
	d, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	var n int
	if err := d.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='attendance_events'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("attendance table missing: %v, %d", err, n)
	}
}
