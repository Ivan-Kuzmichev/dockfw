package daemon

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

const (
	// HeartbeatPath is the file the daemon touches while it is alive.
	HeartbeatPath = "/tmp/dockfw.alive"
	// HeartbeatInterval is how often the heartbeat file is rewritten.
	HeartbeatInterval = 10 * time.Second
	// HeartbeatMaxAge is how old the heartbeat may get before healthz fails.
	HeartbeatMaxAge = 30 * time.Second
)

// WriteHeartbeat records the current time in the heartbeat file.
func WriteHeartbeat(path string, now time.Time) error {
	return os.WriteFile(path, []byte(strconv.FormatInt(now.Unix(), 10)+"\n"), 0o600)
}

// CheckHeartbeat returns an error unless the heartbeat file was written less
// than maxAge ago.
func CheckHeartbeat(path string, maxAge time.Duration, now time.Time) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if age := now.Sub(st.ModTime()); age > maxAge {
		return fmt.Errorf("heartbeat is %s old (max %s)", age.Round(time.Second), maxAge)
	}
	return nil
}
