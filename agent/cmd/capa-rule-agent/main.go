// Command capa-rule-agent prepares evidence-grounded candidate rules and local validation reports.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"capathy/agent/internal/config"
	"capathy/agent/internal/grounding"
	"capathy/agent/internal/intake"
	"capathy/agent/internal/proposal"
	"capathy/agent/internal/publish"
	"capathy/agent/internal/request"
	"capathy/agent/internal/state"
	"capathy/agent/internal/validate"
	"capathy/agent/internal/workflow"
	"strings"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "capa-rule-agent:", err)
		os.Exit(1)
	}
}
func emit(w io.Writer, value any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
func readJSON(ctx context.Context, path string, value any) error {
	data, err := intake.ReadFile(ctx, path, 32<<20)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}
func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: capa-rule-agent <draft|validate|manifest|audit|publish|version> [options]")
	}
	switch args[0] {
	case "version":
		return emit(out, map[string]any{"version": "0.1.0", "schema": 1, "publication_enabled": false})
	case "publish":
		return publish.Publish()
	case "issues":
		return issuesCLI(ctx, args[1:], out)
	case "feed":
		return feedCLI(ctx, args[1:], out)
	case "ground":
		return groundCLI(ctx, args[1:], out)
	case "review-key":
		return reviewKeyCLI(ctx, args[1:], out)
	case "draft":
		return draft(ctx, args[1:], out)
	case "validate":
		return validateCLI(ctx, args[1:], out)
	case "manifest":
		return manifest(ctx, args[1:], out)
	case "audit":
		return audit(ctx, args[1:], out)
	default:
		return errors.New("unknown command")
	}
}
func draft(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("draft", flag.ContinueOnError)
	sample := flags.String("sample", "", "operator-owned sample path (hash only; never executed)")
	capaJSON := flags.String("capa-json", "", "existing capa JSON including parser metadata for scripts")
	requestPath := flags.String("request", "", "normalized request JSON")
	capability := flags.String("capability", "", "capability to investigate")
	shareable := flags.Bool("shareable", false, "operator attests local sample may be publicly shared")
	real := flags.Bool("real", false, "operator attests local positive is a genuine sample, not synthetic")
	recorded := flags.String("proposal", "", "recorded structured proposal JSON for offline replay")
	live := flags.Bool("live", false, "explicitly enable hosted Gemini drafting of evidence only")
	dotenv := flags.String("env-file", "", "explicit dotenv file (optional; never copied)")
	output := flags.String("out", "", "private output JSON file, otherwise stdout")
	dryRun := flags.Bool("dry-run", true, "local output only (always true in this release)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	_ = dryRun
	selected := 0
	for _, path := range []string{*sample, *capaJSON, *requestPath} {
		if path != "" {
			selected++
		}
	}
	if selected != 1 {
		return errors.New("select exactly one of --sample, --capa-json or --request")
	}
	var r request.RuleRequest
	var err error
	if *sample != "" {
		r, err = intake.FromLocal(ctx, *sample, *capability, *shareable)
		if err == nil {
			r.Samples[0].Real = *real
		}
	} else if *capaJSON != "" {
		r, err = intake.FromCapaResult(ctx, *capaJSON, *capability)
	} else {
		var data []byte
		data, err = intake.ReadFile(ctx, *requestPath, 32<<20)
		if err == nil {
			r, err = intake.DecodeRequest(data)
		}
	}
	if err != nil {
		return err
	}
	var value any = r
	if *live && *recorded != "" {
		return errors.New("choose --live or --proposal, not both")
	}
	if *recorded != "" || *live {
		var model workflow.Model
		if *recorded != "" {
			data, err := intake.ReadFile(ctx, *recorded, 1<<20)
			if err != nil {
				return err
			}
			p, err := proposal.Decode(data)
			if err != nil {
				return err
			}
			model = workflow.RecordedModel{Proposal: p}
		} else {
			cfg, err := config.Load(*dotenv, os.Getenv)
			if err != nil {
				return err
			}
			model, err = workflow.NewGemini(ctx, cfg)
			if err != nil {
				return err
			}
		}
		p, err := workflow.Draft(ctx, r, model)
		if err != nil {
			return err
		}
		value = struct {
			Request  request.RuleRequest `json:"request"`
			Proposal proposal.Proposal   `json:"proposal"`
		}{r, p}
	}
	if *output != "" {
		file, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if err = emit(file, value); err != nil {
			file.Close()
			return err
		}
		return file.Close()
	}
	return emit(out, value)
}
func validateCLI(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	requestPath := flags.String("request", "", "request JSON with operator-owned sample paths")
	proposalPath := flags.String("proposal", "", "structured candidate proposal JSON")
	lockPath := flags.String("lock", "", "pinned integration lock JSON")
	python := flags.String("python", "python", "trusted Python executable")
	capaRoot := flags.String("capa-root", "", "capa checkout at pinned revision")
	rulesRoot := flags.String("rules-root", "", "rules checkout at pinned revision")
	samplesRoot := flags.String("samples", "", "populated, rights-reviewed sample corpus")
	output := flags.String("out", "", "private local review bundle directory")
	timeout := flags.Duration("timeout", 60*time.Second, "per-tool timeout")
	semanticReview := flags.String("semantic-review", "", "explicit human overlap-review attestation key for this candidate/rules revision")
	dryRun := flags.Bool("dry-run", true, "local validation only")
	if err := flags.Parse(args); err != nil {
		return err
	}
	_ = dryRun
	data, err := intake.ReadFile(ctx, *requestPath, 32<<20)
	if err != nil {
		return err
	}
	r, err := intake.DecodeRequest(data)
	if err != nil {
		return err
	}
	data, err = intake.ReadFile(ctx, *proposalPath, 1<<20)
	if err != nil {
		return err
	}
	p, err := proposal.Decode(data)
	if err != nil {
		return err
	}
	var lock validate.Lock
	if err = readJSON(ctx, *lockPath, &lock); err != nil {
		return err
	}
	report, err := validate.Validate(ctx, r, p, validate.Options{Python: *python, CapaRoot: *capaRoot, RulesRoot: *rulesRoot, SamplesRoot: *samplesRoot, Lock: lock, SemanticReview: *semanticReview}, validate.ExecRunner{Timeout: *timeout})
	if err != nil {
		return err
	}
	if *output != "" {
		if err = publish.WriteTriage(*output, r, p, report); err != nil {
			return err
		}
		if report.Eligible {
			pkg, err := publish.Build(r, p, report, lock)
			if err != nil {
				return err
			}
			if err = publish.WritePackage(*output, pkg); err != nil {
				return err
			}
		}
	}
	return emit(out, report)
}
func manifest(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
	path := flags.String("request", "", "request JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	b, err := intake.ReadFile(ctx, *path, 32<<20)
	if err != nil {
		return err
	}
	r, err := intake.DecodeRequest(b)
	if err != nil {
		return err
	}
	samples := append([]request.SampleRef(nil), r.Samples...)
	for i := range samples {
		samples[i].Path = ""
	}
	return emit(out, map[string]string{"sample_manifest_hash": validate.DigestJSON(samples)})
}
func audit(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("audit", flag.ContinueOnError)
	path := flags.String("state", "state.db", "local SQLite state file")
	key := flags.String("key", "", "idempotency key")
	claim := flags.Bool("claim", false, "atomically claim the key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *key == "" {
		return errors.New("--key required")
	}
	store, err := state.Open(*path)
	if err != nil {
		return err
	}
	defer store.Close()
	if *claim {
		claimed, err := store.Claim(ctx, *key)
		if err != nil {
			return err
		}
		return emit(out, map[string]bool{"claimed": claimed})
	}
	events, err := store.Get(ctx, *key)
	if err != nil {
		return err
	}
	return emit(out, events)
}

func issuesCLI(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("issues", flag.ContinueOnError)
	path := flags.String("fixture", "", "recorded GitHub issues JSON (read-only offline intake)")
	repo := flags.String("repo", "mandiant/capa-rules", "allowlisted repository")
	if err := flags.Parse(args); err != nil {
		return err
	}
	data, err := intake.ReadFile(ctx, *path, 1<<20)
	if err != nil {
		return err
	}
	requests, err := intake.ParseIssues(data, *repo, []string{"mandiant/capa-rules"})
	if err != nil {
		return err
	}
	return emit(out, requests)
}
func feedCLI(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("feed", flag.ContinueOnError)
	path := flags.String("fixture", "", "recorded RSS, Atom or JSON feed")
	source := flags.String("url", "", "original feed HTTPS URL")
	hosts := flags.String("allow-hosts", "", "explicit comma-separated approved feed/link hosts")
	if err := flags.Parse(args); err != nil {
		return err
	}
	data, err := intake.ReadFile(ctx, *path, 1<<20)
	if err != nil {
		return err
	}
	requests, err := intake.ParseFeed(data, *source, strings.Split(*hosts, ","))
	if err != nil {
		return err
	}
	return emit(out, requests)
}
func groundCLI(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("ground", flag.ContinueOnError)
	target := flags.String("url", "", "official documentation HTTPS URL")
	allowed := flags.String("allow-url", "", "operator-approved exact HTTPS URL")
	if err := flags.Parse(args); err != nil {
		return err
	}
	doc, err := grounding.Retrieve(ctx, *target, grounding.Policy{URLs: []string{*allowed}, Domains: []string{"learn.microsoft.com", "docs.python.org", "www.gnu.org"}}, grounding.HTTPFetcher{})
	if err != nil {
		return err
	}
	return emit(out, doc)
}
func reviewKeyCLI(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("review-key", flag.ContinueOnError)
	path := flags.String("proposal", "", "candidate proposal JSON")
	lockPath := flags.String("lock", "", "integration lock JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	data, err := intake.ReadFile(ctx, *path, 1<<20)
	if err != nil {
		return err
	}
	p, err := proposal.Decode(data)
	if err != nil {
		return err
	}
	var lock validate.Lock
	if err = readJSON(ctx, *lockPath, &lock); err != nil {
		return err
	}
	return emit(out, map[string]string{"semantic_review": validate.SemanticReviewKey(p, lock)})
}
