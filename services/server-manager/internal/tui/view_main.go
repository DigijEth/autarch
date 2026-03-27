package tui

import tea "github.com/charmbracelet/bubbletea"

func (a App) handleMainMenu(key string) (tea.Model, tea.Cmd) {
	// Number key shortcut
	for _, item := range a.mainMenu {
		if key == item.Key {
			if item.Key == "q" {
				return a, tea.Quit
			}
			return a.navigateToView(item.View)
		}
	}

	// Enter on selected item
	if key == "enter" {
		if a.cursor >= 0 && a.cursor < len(a.mainMenu) {
			item := a.mainMenu[a.cursor]
			if item.Key == "q" {
				return a, tea.Quit
			}
			return a.navigateToView(item.View)
		}
	}

	return a, nil
}

func (a App) navigateToView(v ViewID) (tea.Model, tea.Cmd) {
	a.pushView(v)

	switch v {
	case ViewDeploy:
		// Static menu, no async loading
	case ViewDeps:
		// Load dependency status
		return a, a.loadDepsStatus()
	case ViewModules:
		return a, a.loadModules()
	case ViewSettings:
		return a, a.loadSettings()
	case ViewUsers:
		// Static menu, no loading
	case ViewService:
		return a, a.loadServiceStatus()
	case ViewDNS:
		// Static menu
	}

	return a, nil
}
