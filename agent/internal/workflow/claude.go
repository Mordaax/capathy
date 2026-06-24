package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Mordaax/capathy/agent/internal/config"
	"github.com/Mordaax/capathy/agent/internal/proposal"
)

// ClaudeModel drafts evidence-only proposals through Anthropic's Messages API.
type ClaudeModel struct {
	client    *http.Client
	endpoint  string
	model     string
	key       config.Secret
	maxTokens int32
}

// NewClaude creates the opt-in provider with fixed HTTPS routing and no tools.
func NewClaude(ctx context.Context, cfg config.Config) (*ClaudeModel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.APIKey.Reveal() == "" {
		return nil, errors.New("live Claude drafting requires ANTHROPIC_API_KEY or CLAUDE_API_KEY")
	}
	client := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("model redirects are disabled") }}
	return &ClaudeModel{client: client, endpoint: "https://api.anthropic.com/v1/messages", model: cfg.ModelName, key: cfg.APIKey, maxTokens: cfg.MaxOutputTokens}, nil
}

// Draft keeps credentials in HTTP headers and never includes local sample paths in input.
func (m *ClaudeModel) Draft(ctx context.Context, input DraftInput) (proposal.Proposal, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	evidence, err := json.Marshal(input)
	if err != nil {
		return proposal.Proposal{}, err
	}
	if len(evidence) > 2<<20 {
		return proposal.Proposal{}, errors.New("model input exceeds 2 MiB")
	}
	payload := map[string]any{"model": m.model, "max_tokens": m.maxTokens, "system": instruction,
		"messages":      []any{map[string]any{"role": "user", "content": string(evidence)}},
		"output_config": map[string]any{"effort": "low", "format": map[string]any{"type": "json_schema", "schema": proposalSchema(input)}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return proposal.Proposal{}, err
	}
	if len(body) > 4<<20 {
		return proposal.Proposal{}, errors.New("model request exceeds 4 MiB")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint, bytes.NewReader(body))
	if err != nil {
		return proposal.Proposal{}, errors.New("invalid model endpoint")
	}
	req.Header.Set("x-api-key", m.key.Reveal())
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")
	response, err := m.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return proposal.Proposal{}, errors.New("Claude drafting timed out (remote details withheld)")
		}
		return proposal.Proposal{}, errors.New("Claude network request failed (remote details withheld)")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return proposal.Proposal{}, errors.New("read Claude response failed")
	}
	if len(raw) > 1<<20 {
		return proposal.Proposal{}, errors.New("Claude response exceeds 1 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return proposal.Proposal{}, fmt.Errorf("Claude drafting failed (HTTP %d; remote details withheld)", response.StatusCode)
	}
	var result struct {
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return proposal.Proposal{}, errors.New("invalid Claude response JSON")
	}
	if result.StopReason != "end_turn" {
		return proposal.Proposal{}, errors.New("Claude response was incomplete or requested a tool")
	}
	var text strings.Builder
	for _, block := range result.Content {
		switch block.Type {
		case "text":
			text.WriteString(block.Text)
		case "thinking", "redacted_thinking":
		default:
			return proposal.Proposal{}, errors.New("Claude attempted an unrequested tool or content type")
		}
	}
	return proposal.Decode([]byte(text.String()))
}
