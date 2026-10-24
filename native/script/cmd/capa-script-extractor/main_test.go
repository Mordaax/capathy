package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCLI(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		input  string
		status int
	}{
		{"version", []string{"--version"}, "", 0},
		{"analyze", []string{"analyze", "--language", "powershell"}, "Invoke-WebRequest hi", 0},
		{"invalid-language", []string{"analyze", "--language", "ruby"}, "hello", 2},
		{"malformed-encoding", []string{"analyze", "--language", "python"}, string([]byte{0xff}), 2},
		{"missing-language", []string{"analyze"}, "hello", 2},
		{"invalid-command", []string{"run"}, "hello", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, err bytes.Buffer
			code := run(tc.args, strings.NewReader(tc.input), &out, &err)
			if code != tc.status {
				t.Fatalf("status %d stderr %s", code, err.String())
			}
			if code == 0 {
				var v map[string]any
				if e := json.Unmarshal(out.Bytes(), &v); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}
