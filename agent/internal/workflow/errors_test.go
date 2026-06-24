package workflow

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/genai"
)

func TestGeminiFailureKeepsHTTPStatusWithoutCredentials(t *testing.T) {
	secret := "PRIVATE_API_KEY_VALUE"
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{"quota", fmt.Errorf("request key=%s: %w", secret, genai.APIError{Code: 429, Status: "RESOURCE_EXHAUSTED", Message: secret}), "HTTP 429; RESOURCE_EXHAUSTED"},
		{"invalid request", genai.APIError{Code: 400, Status: "INVALID_ARGUMENT", Message: secret}, "HTTP 400; INVALID_ARGUMENT"},
		{"untrusted status", genai.APIError{Code: 403, Status: "token=" + secret, Message: secret}, "HTTP 403; UNKNOWN"},
		{"deadline", context.DeadlineExceeded, "timed out"},
		{"unknown", fmt.Errorf("private endpoint key=%s", secret), "remote details withheld"},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := geminiFailure(test.err).Error()
			if !strings.Contains(message, test.want) || strings.Contains(message, secret) {
				t.Fatalf("incorrect or unredacted failure: %s", message)
			}
		})
	}
}
