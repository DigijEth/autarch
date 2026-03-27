// Package config provides INI-style configuration file parsing and editing
// for autarch_settings.conf. It preserves comments and formatting.
package config

import (
	"fmt"
	"os"
	"strings"
)

// ListSections returns all [section] names from an INI file.
func ListSections(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var sections []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec := line[1 : len(line)-1]
			sections = append(sections, sec)
		}
	}
	return sections, nil
}

// GetSection returns all key-value pairs from a specific section.
func GetSection(path, section string) (keys []string, vals []string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}

	inSection := false
	target := "[" + section + "]"

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)

		// Check for section headers
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inSection = (trimmed == target)
			continue
		}

		if !inSection {
			continue
		}

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}

		// Parse key = value
		eqIdx := strings.Index(trimmed, "=")
		if eqIdx < 0 {
			continue
		}

		key := strings.TrimSpace(trimmed[:eqIdx])
		val := strings.TrimSpace(trimmed[eqIdx+1:])
		keys = append(keys, key)
		vals = append(vals, val)
	}

	return keys, vals, nil
}

// SetValue updates a single key in a section within the INI content string.
// Returns the modified content. If the key doesn't exist, it's appended to the section.
func SetValue(content, section, key, value string) string {
	lines := strings.Split(content, "\n")
	target := "[" + section + "]"
	inSection := false
	found := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			// If we were in our target section and didn't find the key, insert before this line
			if inSection && !found {
				lines[i] = key + " = " + value + "\n" + line
				found = true
			}
			inSection = (trimmed == target)
			continue
		}

		if !inSection {
			continue
		}

		// Check if this line matches our key
		eqIdx := strings.Index(trimmed, "=")
		if eqIdx < 0 {
			continue
		}

		lineKey := strings.TrimSpace(trimmed[:eqIdx])
		if lineKey == key {
			lines[i] = key + " = " + value
			found = true
		}
	}

	// If key wasn't found and we're still in section (or section was last), append
	if !found {
		if inSection {
			lines = append(lines, key+" = "+value)
		}
	}

	return strings.Join(lines, "\n")
}

// GetValue reads a single value from a section.
func GetValue(path, section, key string) (string, error) {
	keys, vals, err := GetSection(path, section)
	if err != nil {
		return "", err
	}
	for i, k := range keys {
		if k == key {
			return vals[i], nil
		}
	}
	return "", fmt.Errorf("key %q not found in [%s]", key, section)
}
