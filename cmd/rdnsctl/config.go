package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	redundantdns "github.com/redundantdns/go-client"
)

// config is the saved state of rdnsctl login. The file holds a token: it is
// written with mode 0600 in a 0700 directory.
type config struct {
	BaseURL string `json:"baseUrl"`
	Token   string `json:"token"`
	OrgID   string `json:"orgId,omitempty"`
	OrgName string `json:"orgName,omitempty"`
	Email   string `json:"email,omitempty"`
	TokenID string `json:"tokenId,omitempty"`
}

// configPath returns --config, or $XDG_CONFIG_HOME/rdnsctl/config.json
// (falling back to the OS user config directory, ~/.config on Linux).
func (cli *app) configPath(shared *globals) (string, error) {
	if shared.configPath != "" {
		return shared.configPath, nil
	}
	base := cli.getenv("XDG_CONFIG_HOME")
	if base == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("locate the config directory: %w", err)
		}
		base = dir
	}
	return filepath.Join(base, "rdnsctl", "config.json"), nil
}

// loadConfig reads the config file; a missing file is an empty config.
func loadConfig(path string) (config, error) {
	var saved config
	raw, err := os.ReadFile(path) //nolint:gosec // the path is the user's own config file
	if errors.Is(err, fs.ErrNotExist) {
		return saved, nil
	}
	if err != nil {
		return saved, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &saved); err != nil {
		return saved, fmt.Errorf("parse %s: %w", path, err)
	}
	return saved, nil
}

// saveConfig writes the config file atomically with mode 0600.
func saveConfig(path string, saved config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	raw, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".config-*.json")
	if err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	defer func() { _ = os.Remove(temporary.Name()) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if _, err := temporary.Write(append(raw, '\n')); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(temporary.Name(), path); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// settings resolves base URL, token and org: flags, then environment, then
// the saved config.
func (cli *app) settings(shared *globals) (config, error) {
	path, err := cli.configPath(shared)
	if err != nil {
		return config{}, err
	}
	saved, err := loadConfig(path)
	if err != nil {
		return config{}, err
	}
	resolved := saved
	resolved.BaseURL = firstNonEmpty(shared.baseURL, cli.getenv("RDNS_BASE_URL"), saved.BaseURL, redundantdns.DefaultBaseURL)
	resolved.Token = firstNonEmpty(shared.token, cli.getenv("RDNS_TOKEN"), saved.Token)
	resolved.OrgID = firstNonEmpty(shared.org, cli.getenv("RDNS_ORG"), saved.OrgID)
	return resolved, nil
}

// client builds an API client from the resolved settings. It fails early
// when there is no token.
func (cli *app) client(shared *globals) (*redundantdns.Client, error) {
	resolved, err := cli.settings(shared)
	if err != nil {
		return nil, err
	}
	if resolved.Token == "" {
		return nil, errors.New("not signed in: run rdnsctl login, or pass --token / set RDNS_TOKEN")
	}
	return redundantdns.New(
		redundantdns.WithBaseURL(resolved.BaseURL),
		redundantdns.WithToken(resolved.Token),
		redundantdns.WithOrg(resolved.OrgID),
		redundantdns.WithUserAgent("rdnsctl/"+version),
	)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
