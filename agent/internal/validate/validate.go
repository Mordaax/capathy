package validate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mordaax/capathy/agent/internal/intake"
	"github.com/Mordaax/capathy/agent/internal/proposal"
	"github.com/Mordaax/capathy/agent/internal/request"
)

// DigestJSON computes the canonical digest used to bind reports to immutable inputs.
func DigestJSON(value any) string { b, _ := json.Marshal(value); return request.Hash(b) }

// Validate builds a disposable pinned rules worktree, invokes official tools, then checks exact positive and negative matches.
func Validate(ctx context.Context, r request.RuleRequest, p proposal.Proposal, opt Options, runner Runner) (report Report, returnErr error) {
	report = Report{Schema: 1, RequestID: r.ID, RequestSHA256: DigestJSON(r), RuleSHA256: request.Hash([]byte(p.YAML)), LockSHA256: DigestJSON(opt.Lock), Eligible: true, Checks: []Check{}, Logs: []Log{}}
	if err := QualityGate(r, p, opt.Lock); err != nil {
		report.check("quality", err)
		return report, nil
	}
	report.check("quality", nil)
	if opt.Python == "" || opt.CapaRoot == "" || opt.RulesRoot == "" || opt.SamplesRoot == "" {
		report.check("configuration", errors.New("python, capa root, rules root and samples root required"))
		return report, nil
	}
	run := func(name string, c Command) (Log, error) {
		log, err := runner.Run(ctx, c)
		report.Logs = append(report.Logs, log)
		report.check(name, err)
		return log, err
	}
	for _, repo := range []struct{ name, path, revision string }{{"capa", opt.CapaRoot, opt.Lock.CapaRevision}, {"rules", opt.RulesRoot, opt.Lock.RulesRevision}} {
		log, err := run(repo.name+" revision", Command{Program: "git", Args: []string{"-C", repo.path, "rev-parse", "HEAD"}})
		if err != nil {
			return report, nil
		}
		if strings.TrimSpace(log.Stdout) != repo.revision {
			report.check(repo.name+" pin", errors.New("checkout does not match lock"))
			return report, nil
		}
		status, statusErr := run(repo.name+" clean checkout", Command{Program: "git", Args: []string{"-C", repo.path, "status", "--porcelain"}})
		if statusErr != nil {
			return report, nil
		}
		if strings.TrimSpace(status.Stdout) != "" {
			report.check(repo.name+" clean pin", errors.New("checkout contains uncommitted changes"))
			return report, nil
		}
	}
	// Every sample is rehashed. Manifest identity covers role, rights, reality and digest, but not machine-specific paths.
	manifest := []request.SampleRef{}
	verifiedPaths := map[string]string{}
	for _, sample := range r.Samples {
		path, err := samplePath(opt.SamplesRoot, sample.Path)
		if err != nil {
			report.check("sample confinement", err)
			return report, nil
		}
		data, err := intake.ReadFile(ctx, path, request.MaxInput)
		if err != nil || request.Hash(data) != sample.SHA256 {
			report.check("sample hash", errors.New("sample missing or hash mismatch"))
			return report, nil
		}
		verifiedPaths[sample.SHA256] = path
		sample.Path = ""
		manifest = append(manifest, sample)
	}
	if DigestJSON(manifest) != opt.Lock.SampleManifestHash {
		report.check("sample manifest", errors.New("sample manifest does not match lock"))
		return report, nil
	}
	report.check("sample manifest", nil)
	temp, err := os.MkdirTemp("", "capa-rule-agent-")
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(temp)
	worktree := filepath.Join(temp, "rules")
	if _, err = run("rules worktree", Command{Program: "git", Args: []string{"-C", opt.RulesRoot, "worktree", "add", "--detach", worktree, opt.Lock.RulesRevision}}); err != nil {
		return report, nil
	}
	defer func() {
		_, cleanupErr := runner.Run(context.WithoutCancel(ctx), Command{Program: "git", Args: []string{"-C", opt.RulesRoot, "worktree", "remove", "--force", worktree}})
		if cleanupErr != nil && returnErr == nil {
			returnErr = fmt.Errorf("cleanup rules worktree: %w", cleanupErr)
		}
	}()
	rule, err := proposal.ParseRule(p.YAML)
	if err != nil {
		report.check("rule schema", err)
		return report, nil
	}
	// Duplicate names are deterministic; semantic overlap still requires human review and therefore blocks publication below.
	duplicate := false
	walkErr := filepath.WalkDir(worktree, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".yml" && filepath.Ext(path) != ".yaml" {
			return nil
		}
		data, err := intake.ReadFile(ctx, path, 1<<20)
		if err != nil {
			return err
		}
		existing, err := proposal.ParseRule(string(data))
		if err == nil && existing.Rule.Meta.Name == rule.Rule.Meta.Name {
			duplicate = true
		}
		return nil
	})
	if walkErr != nil || duplicate {
		report.check("duplicate rule", errors.New("existing rule name or unreadable rules corpus"))
		return report, nil
	}
	report.check("duplicate rule name", nil)
	filename, err := proposal.Filename(rule)
	if err != nil {
		report.check("rule filename", err)
		return report, nil
	}
	candidate := filepath.Join(worktree, "nursery", filename)
	if err = os.MkdirAll(filepath.Dir(candidate), 0700); err != nil {
		return report, err
	}
	info, err := os.Lstat(filepath.Dir(candidate))
	if err != nil || !info.IsDir() {
		report.check("candidate directory", errors.New("nursery must be a real directory"))
		return report, nil
	}
	candidateFile, err := os.OpenFile(candidate, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return report, err
	}
	if _, err = candidateFile.Write([]byte(p.YAML)); err != nil {
		candidateFile.Close()
		return report, err
	}
	if err = candidateFile.Close(); err != nil {
		return report, err
	}
	if _, err = run("formatter", Command{Program: opt.Python, Args: []string{filepath.Join(opt.CapaRoot, "scripts", "capafmt.py"), "-c", candidate}, Dir: opt.CapaRoot}); err != nil {
		return report, nil
	}
	absoluteSamples, err := filepath.Abs(opt.SamplesRoot)
	if err != nil {
		return report, err
	}
	if _, err = run("thorough linter", Command{Program: opt.Python, Args: []string{filepath.Join(opt.CapaRoot, "scripts", "lint.py"), "--thorough", "--samples", absoluteSamples, worktree}, Dir: opt.CapaRoot}); err != nil {
		return report, nil
	}
	for _, sample := range r.Samples {
		format := sample.Language
		if format == "" {
			format = "auto"
		}
		switch format {
		case "auto", "pe", "elf", "dotnet", "sc32", "sc64", "powershell", "python", "bash", "javascript", "typescript", "c", "cpp":
		default:
			report.check("sample format", errors.New("unsupported format"))
			return report, nil
		}
		log, err := run("sample scan", Command{Program: opt.Python, Args: []string{"-m", "capa.main", "-j", "-q", "-r", worktree, "-f", format, verifiedPaths[sample.SHA256]}, Dir: opt.CapaRoot})
		if err != nil {
			return report, nil
		}
		// Persist a digest of capa JSON, not sample-derived strings from the full evidence document.
		report.Logs[len(report.Logs)-1].Stdout = "capa-result-sha256: " + request.Hash([]byte(log.Stdout))
		var result struct {
			Meta struct {
				Sample struct {
					SHA256 string `json:"sha256"`
				} `json:"sample"`
			} `json:"meta"`
			Rules map[string]struct {
				Matches []json.RawMessage `json:"matches"`
			} `json:"rules"`
		}
		if err = json.Unmarshal([]byte(log.Stdout), &result); err != nil || result.Rules == nil {
			report.check("sample result", errors.New("invalid capa result"))
			return report, nil
		}
		if result.Meta.Sample.SHA256 != sample.SHA256 {
			report.check("sample result hash", errors.New("capa result does not identify the exact verified sample"))
			return report, nil
		}
		matched := len(result.Rules[rule.Rule.Meta.Name].Matches) > 0
		if sample.Role == "positive" {
			if !matched {
				report.check("positive sample", errors.New("candidate misses a real positive"))
				return report, nil
			}
			report.PositiveMatches++
		} else if matched {
			report.NegativeMatches++
			report.check("negative sample", errors.New("candidate matches a negative"))
			return report, nil
		}
	}
	report.check("exact sample matches", nil)
	if opt.SemanticReview != SemanticReviewKey(p, opt.Lock) {
		report.check("semantic duplicate review", errors.New("explicit human semantic overlap review attestation is required for this candidate and rules revision"))
	} else {
		report.check("semantic duplicate review", nil)
	}
	return report, nil
}
