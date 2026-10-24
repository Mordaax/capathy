// Package validate runs fixed capa tooling and fails closed on missing evidence or sample gates.
package validate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Command is an operator-selected tool and fixed argument vector; no shell is used.
type Command struct {
	Program string   `json:"program"`
	Args    []string `json:"args"`
	Dir     string   `json:"dir"`
}

// Log records a bounded subprocess outcome, without sample contents or process environment.
type Log struct {
	Command    Command `json:"command"`
	ExitCode   int     `json:"exit_code"`
	Stdout     string  `json:"stdout"`
	Stderr     string  `json:"stderr"`
	DurationMS int64   `json:"duration_ms"`
}

// Runner is injectable for replay; only Validation constructs command arguments.
type Runner interface {
	Run(context.Context, Command) (Log, error)
}

// ExecRunner executes trusted installed tools with deadline and output caps.
type ExecRunner struct {
	Timeout   time.Duration
	MaxOutput int
}
type cappedBuffer struct {
	buffer   bytes.Buffer
	max      int
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.max - b.buffer.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buffer.Write(p[:remaining])
		} else {
			_, _ = b.buffer.Write(p)
		}
	}
	if n > remaining {
		b.exceeded = true
		return n, errors.New("command output limit exceeded")
	}
	return n, nil
}

// Run excludes credentials from subprocess environments and never evaluates a shell expression.
func (r ExecRunner) Run(ctx context.Context, c Command) (Log, error) {
	if r.Timeout == 0 {
		r.Timeout = 60 * time.Second
	}
	if r.MaxOutput == 0 {
		r.MaxOutput = 32 << 20
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Program, c.Args...)
	cmd.Dir = c.Dir
	cmd.WaitDelay = 2 * time.Second
	cmd.Env = []string{}
	for _, item := range os.Environ() {
		k, _, _ := strings.Cut(item, "=")
		if k == "PATH" || k == "HOME" || k == "SYSTEMROOT" || k == "TMPDIR" || k == "CAPA_SCRIPT_EXTRACTOR" || k == "VIRTUAL_ENV" {
			cmd.Env = append(cmd.Env, item)
		}
	}
	stdout, stderr := &cappedBuffer{max: r.MaxOutput}, &cappedBuffer{max: 65536}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	start := time.Now()
	err := cmd.Run()
	code := 0
	if err != nil {
		code = -1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
	}
	log := Log{Command: c, ExitCode: code, Stdout: stdout.buffer.String(), Stderr: stderr.buffer.String(), DurationMS: time.Since(start).Milliseconds()}
	if stdout.exceeded || stderr.exceeded {
		return log, errors.New("command output limit exceeded")
	}
	if ctx.Err() != nil {
		return log, ctx.Err()
	}
	if err != nil {
		return log, fmt.Errorf("tool failed with exit %d", code)
	}
	return log, nil
}
