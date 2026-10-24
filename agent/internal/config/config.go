// Package config loads operator-owned settings and keeps credentials out of logs.
package config

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Secret conceals credentials from JSON, fmt and slog's default formatter.
type Secret struct{ value string }

// Reveal returns the credential only at the model client boundary.
func (s Secret) Reveal() string                { return s.value }
func (s Secret) String() string                { return "[REDACTED]" }
func (s Secret) GoString() string              { return "[REDACTED]" }
func (s Secret) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, "[REDACTED]") }
func (s Secret) MarshalJSON() ([]byte, error)  { return json.Marshal("[REDACTED]") }

// Config contains safe defaults. Publication is intentionally disabled in this initial implementation.
type Config struct {
	ModelName          string `json:"model_name"`
	APIKey             Secret `json:"-"`
	MaxOutputTokens    int32  `json:"max_output_tokens"`
	DisablePublication bool   `json:"disable_publication"`
}

// Load reads an explicitly selected dotenv file; process credentials take precedence over all file credentials.
func Load(dotenv string, getenv func(string) string) (Config, error) {
	cfg := Config{ModelName: "gemini-2.5-flash", MaxOutputTokens: 8192, DisablePublication: true}
	vars := map[string]string{}
	if dotenv != "" {
		f, err := os.Open(dotenv)
		if err != nil {
			return cfg, fmt.Errorf("open dotenv: %w", err)
		}
		defer f.Close()
		s := bufio.NewScanner(io.LimitReader(f, 65537))
		s.Buffer(make([]byte, 4096), 65536)
		total := 0
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			total += len(line)
			if total > 65536 {
				return cfg, errors.New("dotenv too large")
			}
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			line = strings.TrimPrefix(line, "export ")
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				return cfg, errors.New("invalid dotenv assignment")
			}
			vars[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), "\"'")
		}
		if err := s.Err(); err != nil {
			return cfg, fmt.Errorf("read dotenv: %w", err)
		}
	}
	for _, source := range []func(string) string{getenv, func(k string) string { return vars[k] }} {
		for _, key := range []string{"GOOGLE_API_KEY", "GEMINI_API_KEY"} {
			if value := source(key); value != "" {
				cfg.APIKey = Secret{value}
				break
			}
		}
		if cfg.APIKey.value != "" {
			break
		}
	}
	if name := getenv("CAPA_AGENT_MODEL"); name != "" {
		cfg.ModelName = name
	}
	return cfg, nil
}
