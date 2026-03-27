// Package users manages AUTARCH web dashboard credentials.
// Credentials are stored in data/web_credentials.json as bcrypt hashes.
package users

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
)

// Credentials matches the Python web_credentials.json format.
type Credentials struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	ForceChange bool   `json:"force_change"`
}

func credentialsPath(autarchDir string) string {
	return filepath.Join(autarchDir, "data", "web_credentials.json")
}

// LoadCredentials reads the current credentials from disk.
func LoadCredentials(autarchDir string) (*Credentials, error) {
	path := credentialsPath(autarchDir)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials: %w", err)
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}
	return &creds, nil
}

// SaveCredentials writes credentials to disk.
func SaveCredentials(autarchDir string, creds *Credentials) error {
	path := credentialsPath(autarchDir)

	// Ensure data directory exists
	os.MkdirAll(filepath.Dir(path), 0755)

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	return nil
}

// CreateUser creates a new user with bcrypt-hashed password.
func CreateUser(autarchDir, username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	creds := &Credentials{
		Username:    username,
		Password:    string(hash),
		ForceChange: false,
	}
	return SaveCredentials(autarchDir, creds)
}

// ResetPassword changes the password for the existing user.
func ResetPassword(autarchDir, newPassword string) error {
	creds, err := LoadCredentials(autarchDir)
	if err != nil {
		// If no file exists, create with default username
		creds = &Credentials{Username: "admin"}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	creds.Password = string(hash)
	creds.ForceChange = false
	return SaveCredentials(autarchDir, creds)
}

// SetForceChange sets the force_change flag.
func SetForceChange(autarchDir string, force bool) error {
	creds, err := LoadCredentials(autarchDir)
	if err != nil {
		return err
	}
	creds.ForceChange = force
	return SaveCredentials(autarchDir, creds)
}

// ResetToDefaults resets credentials to admin/admin with force change.
func ResetToDefaults(autarchDir string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	creds := &Credentials{
		Username:    "admin",
		Password:    string(hash),
		ForceChange: true,
	}
	return SaveCredentials(autarchDir, creds)
}
