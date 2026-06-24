package workflow

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/genai"
)

// geminiFailure retains actionable status while withholding URLs, messages and details.
func geminiFailure(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("Gemini drafting timed out (remote details withheld)")
	}
	var api genai.APIError
	matched := errors.As(err, &api)
	if !matched {
		var pointer *genai.APIError
		if errors.As(err, &pointer) && pointer != nil {
			api = *pointer
			matched = true
		}
	}
	if matched {
		status := "UNKNOWN"
		switch api.Status {
		case "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND",
			"ALREADY_EXISTS", "PERMISSION_DENIED", "UNAUTHENTICATED", "RESOURCE_EXHAUSTED",
			"FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL",
			"UNAVAILABLE", "DATA_LOSS":
			status = api.Status
		}
		return fmt.Errorf("Gemini drafting failed (HTTP %d; %s; remote details withheld)", api.Code, status)
	}
	return fmt.Errorf("Gemini drafting failed (%T; remote details withheld)", err)
}
