// Package intake accepts operator-owned local files and recorded public source data.
package intake

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"capathy/agent/internal/evidence"
	"capathy/agent/internal/request"
)

// ReadFile reads a regular, non-symlink local file under a byte cap.
func ReadFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("input must be a bounded regular file, not a symlink")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("input changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("input too large")
	}
	return b, ctx.Err()
}

// FromLocal hashes a sample and never executes or logs its bytes.
func FromLocal(ctx context.Context, path, capability string, shareable bool) (request.RuleRequest, error) {
	b, err := ReadFile(ctx, path, request.MaxInput)
	if err != nil {
		return request.RuleRequest{}, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return request.RuleRequest{}, err
	}
	language := ""
	switch filepath.Ext(path) {
	case ".ps1":
		language = "powershell"
	case ".py":
		language = "python"
	case ".sh":
		language = "bash"
	}
	r := request.RuleRequest{Schema: 1, Origin: request.Origin{Kind: "manual", ObservedAt: time.Now().UTC()}, Capability: capability, Language: language, Samples: []request.SampleRef{{SHA256: request.Hash(b), Path: absolute, Role: "positive", Shareable: shareable, Language: language}}}
	r.ID = r.Key()
	return r, r.Validate()
}

// FromCapaResult imports successful evidence from a bounded capa JSON document; imported paths are ignored.
func FromCapaResult(ctx context.Context, path, capability string) (request.RuleRequest, error) {
	b, err := ReadFile(ctx, path, 32<<20)
	if err != nil {
		return request.RuleRequest{}, err
	}
	bundle, err := evidence.Import(b)
	if err != nil {
		return request.RuleRequest{}, err
	}
	r := request.RuleRequest{Schema: 1, Origin: request.Origin{Kind: "capa-json", ObservedAt: time.Now().UTC()}, Capability: capability, Language: bundle.Format, Samples: []request.SampleRef{{SHA256: bundle.SampleSHA256, Role: "positive", Language: bundle.Format}}, Evidence: bundle.Features}
	r.ID = r.Key()
	return r, r.Validate()
}

// DecodeRequest rejects unknown fields and trailing JSON before request validation.
func DecodeRequest(b []byte) (request.RuleRequest, error) {
	var r request.RuleRequest
	if len(b) > 32<<20 {
		return r, fmt.Errorf("request too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return r, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return r, errors.New("trailing request JSON")
	}
	return r, r.Validate()
}
