package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/darkhal/autarch-server-manager/internal/tui"
)

const version = "1.0.0"

func main() {
	if os.Geteuid() != 0 {
		fmt.Println("\033[91m[!] Autarch Server Manager requires root privileges.\033[0m")
		fmt.Println("    Run with: sudo ./autarch-server-manager")
		os.Exit(1)
	}

	p := tea.NewProgram(tui.NewApp(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
