package tui

import (
	"os"
	"path/filepath"
)

// findAutarchDir walks up from the server-manager binary location to find
// the AUTARCH project root (identified by autarch_settings.conf).
func findAutarchDir() string {
	// Try well-known paths first
	candidates := []string{
		"/opt/autarch",
		"/srv/autarch",
		"/home/autarch",
	}

	// Also try relative to the executable
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		// services/server-manager/ → ../../
		candidates = append([]string{
			filepath.Join(dir, "..", ".."),
			filepath.Join(dir, ".."),
			dir,
		}, candidates...)
	}

	// Also check cwd
	if cwd, err := os.Getwd(); err == nil {
		candidates = append([]string{cwd, filepath.Join(cwd, "..", "..")}, candidates...)
	}

	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		conf := filepath.Join(abs, "autarch_settings.conf")
		if _, err := os.Stat(conf); err == nil {
			return abs
		}
	}

	// Fallback
	return "/opt/autarch"
}
