package tui

import (
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

// ── Input View Handling ─────────────────────────────────────────────

func (a App) handleInputKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	switch key {
	case "esc":
		a.popView()
		return a, nil

	case "tab", "shift+tab":
		// Cycle focus
		if key == "tab" {
			a.focusIdx = (a.focusIdx + 1) % len(a.inputs)
		} else {
			a.focusIdx = (a.focusIdx - 1 + len(a.inputs)) % len(a.inputs)
		}
		for i := range a.inputs {
			if i == a.focusIdx {
				a.inputs[i].Focus()
			} else {
				a.inputs[i].Blur()
			}
		}
		return a, nil

	case "enter":
		// If not on last field, advance
		if a.focusIdx < len(a.inputs)-1 {
			a.focusIdx++
			for i := range a.inputs {
				if i == a.focusIdx {
					a.inputs[i].Focus()
				} else {
					a.inputs[i].Blur()
				}
			}
			return a, nil
		}

		// Submit
		switch a.view {
		case ViewUsersCreate:
			return a.submitUserCreate()
		case ViewUsersReset:
			return a.submitUserReset()
		case ViewSettingsEdit:
			return a.saveSettings()
		case ViewDNSZoneEdit:
			return a.submitDNSZone()
		}
		return a, nil
	}

	// Forward key to focused input
	if a.focusIdx >= 0 && a.focusIdx < len(a.inputs) {
		var cmd tea.Cmd
		a.inputs[a.focusIdx], cmd = a.inputs[a.focusIdx].Update(msg)
		return a, cmd
	}

	return a, nil
}

func (a App) updateInputs(msg tea.Msg) (tea.Model, tea.Cmd) {
	if a.focusIdx >= 0 && a.focusIdx < len(a.inputs) {
		var cmd tea.Cmd
		a.inputs[a.focusIdx], cmd = a.inputs[a.focusIdx].Update(msg)
		return a, cmd
	}
	return a, nil
}

// ── File Helpers (used by multiple views) ────────────────────────────

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readFileBytes(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

func renameFile(src, dst string) error {
	return os.Rename(src, dst)
}
