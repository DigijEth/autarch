package tui

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// ── Streaming Messages ──────────────────────────────────────────────

// ProgressMsg updates the progress bar in the output view.
type ProgressMsg struct {
	Step  int
	Total int
	Label string
}

// ── Step Definition ─────────────────────────────────────────────────

// CmdStep defines a single command to run in a streaming sequence.
type CmdStep struct {
	Label string   // Human-readable label (shown in output)
	Args  []string // Command + arguments
	Dir   string   // Working directory (empty = inherit)
}

// ── Streaming Execution Engine ──────────────────────────────────────

// streamSteps runs a sequence of CmdSteps, sending OutputLineMsg per line
// and ProgressMsg per step, then DoneMsg when finished.
// It writes to a buffered channel that the TUI reads via waitForOutput().
func streamSteps(ch chan<- tea.Msg, steps []CmdStep) {
	defer close(ch)

	total := len(steps)
	var errors []string

	for i, step := range steps {
		// Send progress update
		ch <- ProgressMsg{
			Step:  i + 1,
			Total: total,
			Label: step.Label,
		}

		// Show command being executed
		cmdStr := strings.Join(step.Args, " ")
		ch <- OutputLineMsg(styleKey.Render(fmt.Sprintf("═══ [%d/%d] %s ═══", i+1, total, step.Label)))
		ch <- OutputLineMsg(styleDim.Render("  $ " + cmdStr))

		// Build command
		cmd := exec.Command(step.Args[0], step.Args[1:]...)
		if step.Dir != "" {
			cmd.Dir = step.Dir
		}

		// Get pipes for real-time output
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			ch <- OutputLineMsg(styleError.Render("  Failed to create stdout pipe: " + err.Error()))
			errors = append(errors, step.Label+": "+err.Error())
			continue
		}
		cmd.Stderr = cmd.Stdout // merge stderr into stdout

		// Start command
		startTime := time.Now()
		if err := cmd.Start(); err != nil {
			ch <- OutputLineMsg(styleError.Render("  Failed to start: " + err.Error()))
			errors = append(errors, step.Label+": "+err.Error())
			continue
		}

		// Read output line by line
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 256*1024) // handle long lines
		lineCount := 0
		for scanner.Scan() {
			line := scanner.Text()
			lineCount++

			// Parse apt/pip progress indicators for speed display
			if parsed := parseProgressLine(line); parsed != "" {
				ch <- OutputLineMsg("  " + parsed)
			} else {
				// Throttle verbose output: show every line for first 30,
				// then every 5th line, but always show errors
				if lineCount <= 30 || lineCount%5 == 0 || isErrorLine(line) {
					ch <- OutputLineMsg("  " + line)
				}
			}
		}

		// Wait for command to finish
		err = cmd.Wait()
		elapsed := time.Since(startTime)

		if err != nil {
			ch <- OutputLineMsg(styleError.Render(fmt.Sprintf("  ✘ Failed (%s): %s", elapsed.Round(time.Millisecond), err.Error())))
			errors = append(errors, step.Label+": "+err.Error())
		} else {
			ch <- OutputLineMsg(styleSuccess.Render(fmt.Sprintf("  ✔ Done (%s)", elapsed.Round(time.Millisecond))))
		}
		ch <- OutputLineMsg("")
	}

	// Final summary
	if len(errors) > 0 {
		ch <- OutputLineMsg(styleWarning.Render(fmt.Sprintf("═══ Completed with %d error(s) ═══", len(errors))))
		for _, e := range errors {
			ch <- OutputLineMsg(styleError.Render("  ✘ " + e))
		}
		ch <- DoneMsg{Err: fmt.Errorf("%d step(s) failed", len(errors))}
	} else {
		ch <- OutputLineMsg(styleSuccess.Render("═══ All steps completed successfully ═══"))
		ch <- DoneMsg{}
	}
}

// ── Progress Parsing ────────────────────────────────────────────────

// parseProgressLine extracts progress info from apt/pip/npm output.
func parseProgressLine(line string) string {
	// apt progress: "Progress: [ 45%]"  or percentage patterns
	if strings.Contains(line, "Progress:") || strings.Contains(line, "progress:") {
		return styleWarning.Render(strings.TrimSpace(line))
	}

	// pip: "Downloading foo-1.2.3.whl (2.3 MB)" or "Installing collected packages:"
	if strings.HasPrefix(line, "Downloading ") || strings.HasPrefix(line, "Collecting ") {
		return styleCyan.Render(strings.TrimSpace(line))
	}
	if strings.HasPrefix(line, "Installing collected packages:") {
		return styleWarning.Render(strings.TrimSpace(line))
	}

	// npm: "added X packages"
	if strings.Contains(line, "added") && strings.Contains(line, "packages") {
		return styleSuccess.Render(strings.TrimSpace(line))
	}

	return ""
}

// isErrorLine checks if an output line looks like an error.
func isErrorLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "error") ||
		strings.Contains(lower, "failed") ||
		strings.Contains(lower, "fatal") ||
		strings.Contains(lower, "warning") ||
		strings.Contains(lower, "unable to")
}

// ── Style for progress lines ────────────────────────────────────────

var styleCyan = styleKey // reuse existing cyan style
