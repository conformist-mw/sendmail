package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// configPaths are searched in order; the first readable file wins.
var configPaths = []string{
	"sendmail.yaml",
	"/etc/tg-sendmail.yaml",
	"/etc/sendmail.yaml",
}

type Config struct {
	Log struct {
		Level string `yaml:"level"`
		Path  string `yaml:"path"`
	} `yaml:"log"`
	Telegram struct {
		BotToken string `yaml:"bot_token"`
		ChatID   string `yaml:"chat_id"`
	} `yaml:"telegram"`
}

// HasCredentials reports whether the bot can talk to Telegram at all.
func (c Config) HasCredentials() bool {
	return c.Telegram.BotToken != "" && c.Telegram.ChatID != ""
}

var errNoConfig = errors.New("cannot find configuration file")

func cleanValue(value string) string {
	return strings.Trim(strings.TrimSpace(value), `"'`)
}

func loadConfig(paths []string) (Config, error) {
	var cfg Config
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			// An existing but unreadable file is a misconfiguration worth
			// reporting instead of silently falling through to the next path.
			return cfg, fmt.Errorf("cannot read %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("cannot parse %s: %w", path, err)
		}
		// Credentials pasted with surrounding quotes or stray whitespace would
		// otherwise travel into the request URL and come back as a 404.
		cfg.Telegram.BotToken = cleanValue(cfg.Telegram.BotToken)
		cfg.Telegram.ChatID = cleanValue(cfg.Telegram.ChatID)
		return cfg, nil
	}
	return cfg, errNoConfig
}
