package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHeartbeat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alive")
	now := time.Now()

	if err := CheckHeartbeat(path, HeartbeatMaxAge, now); err == nil {
		t.Fatal("missing file must fail")
	}
	if err := WriteHeartbeat(path, now); err != nil {
		t.Fatal(err)
	}
	if err := CheckHeartbeat(path, HeartbeatMaxAge, now); err != nil {
		t.Fatalf("fresh heartbeat failed: %v", err)
	}

	old := now.Add(-time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := CheckHeartbeat(path, HeartbeatMaxAge, now); err == nil {
		t.Fatal("stale heartbeat must fail")
	}
}
