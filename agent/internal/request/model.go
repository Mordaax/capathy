// Package request defines immutable, versioned intake and evidence records.
package request

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const MaxInput = 16 << 20

// Origin records the operator or public source that initiated a request.
type Origin struct {
	Kind       string    `json:"kind"`
	URL        string    `json:"url,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

// SampleRef describes a sample without including its contents.
type SampleRef struct {
	SHA256    string `json:"sha256"`
	Path      string `json:"path,omitempty"`
	Shareable bool   `json:"shareable"`
	Real      bool   `json:"real"`
	Role      string `json:"role"`
	Language  string `json:"language,omitempty"`
}

// Span is a half-open original-file byte interval.
type Span struct {
	Start uint64 `json:"start_byte"`
	End   uint64 `json:"end_byte"`
}

// EvidenceRef is a stable citation to independently collected capa evidence.
type EvidenceRef struct {
	ID               string  `json:"id"`
	SampleSHA256     string  `json:"sample_sha256"`
	Kind             string  `json:"kind"`
	Value            string  `json:"value"`
	Address          *uint64 `json:"address,omitempty"`
	Span             *Span   `json:"span,omitempty"`
	CapaVersion      string  `json:"capa_version"`
	ExtractorVersion string  `json:"extractor_version,omitempty"`
}

// RuleRequest is the schema 1 request envelope. Only manual requests may carry local paths.
type RuleRequest struct {
	Schema     int           `json:"schema"`
	ID         string        `json:"id"`
	Origin     Origin        `json:"origin"`
	Capability string        `json:"capability"`
	Language   string        `json:"language,omitempty"`
	Samples    []SampleRef   `json:"samples"`
	Evidence   []EvidenceRef `json:"evidence"`
	Sources    []string      `json:"sources,omitempty"`
}

// ValidHash reports whether s is a canonical SHA-256 digest.
func ValidHash(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && s == strings.ToLower(s)
}

// Hash returns a canonical SHA-256 digest.
func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Validate rejects unsupported, unbounded, contradictory or ungrounded requests.
func (r RuleRequest) Validate() error {
	if r.Schema != 1 || r.ID == "" || len(r.ID) > 256 || r.Capability == "" || len(r.Capability) > 4096 {
		return errors.New("invalid request schema, identity or capability")
	}
	switch r.Origin.Kind {
	case "manual", "capa-json", "issue", "feed":
	default:
		return errors.New("unsupported origin")
	}
	if len(r.Samples) > 1000 || len(r.Evidence) > 100000 || len(r.Sources) > 100 {
		return errors.New("request count limit exceeded")
	}
	if r.Language != "" && r.Language != "powershell" && r.Language != "python" && r.Language != "bash" && r.Language != "pe" && r.Language != "elf" && r.Language != "dotnet" {
		return errors.New("unsupported language")
	}
	samples := map[string]bool{}
	for _, s := range r.Samples {
		if !ValidHash(s.SHA256) {
			return errors.New("sample SHA-256 required")
		}
		if samples[s.SHA256] {
			return errors.New("duplicate sample")
		}
		samples[s.SHA256] = true
		if s.Path != "" && r.Origin.Kind != "manual" && r.Origin.Kind != "capa-json" {
			return errors.New("remote request cannot select local paths")
		}
		if s.Role != "positive" && s.Role != "benign" && s.Role != "adversarial" {
			return errors.New("unsupported sample role")
		}
	}
	ids := map[string]bool{}
	for _, e := range r.Evidence {
		if e.ID == "" || len(e.ID) > 128 || ids[e.ID] || !samples[e.SampleSHA256] || e.Kind == "" || len(e.Kind) > 128 || len(e.Value) > 65536 || e.CapaVersion == "" {
			return fmt.Errorf("invalid evidence %q", e.ID)
		}
		ids[e.ID] = true
		if e.Span != nil && e.Span.Start > e.Span.End {
			return errors.New("invalid evidence span")
		}
	}
	return nil
}

// Key derives a durable key independent of intake ordering and transient IDs.
func (r RuleRequest) Key() string {
	hashes := make([]string, 0, len(r.Samples))
	for _, s := range r.Samples {
		hashes = append(hashes, s.SHA256)
	}
	sort.Strings(hashes)
	b, _ := json.Marshal(struct {
		Origin     string
		Capability string
		Hashes     []string
	}{r.Origin.Kind + ":" + r.Origin.URL, r.Capability, hashes})
	return Hash(b)
}
