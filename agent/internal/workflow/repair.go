package workflow

import (
	"context"
	"errors"
	"reflect"

	"github.com/Mordaax/capathy/agent/internal/proposal"
	"github.com/Mordaax/capathy/agent/internal/request"
)

// Failure identifies deterministic validator failures; only local rule syntax failures are model-repairable.
type Failure struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// Validator validates candidates using immutable request, paths, tools and destination captured by the caller.
type Validator interface {
	Check(context.Context, proposal.Proposal) ([]Failure, error)
}

// Repair permits at most three total draft/validation attempts, including the supplied first draft.
// Citation sets and all request evidence remain immutable. Non-syntax failures go directly to triage.
func Repair(ctx context.Context, r request.RuleRequest, initial proposal.Proposal, model Model, validator Validator) (proposal.Proposal, []Failure, error) {
	candidate := initial
	seen := map[string]bool{}
	for attempt := 0; attempt < 3; attempt++ {
		if err := candidate.ValidateReferences(r); err != nil {
			return candidate, nil, err
		}
		if seen[request.Hash([]byte(candidate.YAML))] {
			return candidate, nil, errors.New("repair repeated identical YAML")
		}
		seen[request.Hash([]byte(candidate.YAML))] = true
		failures, err := validator.Check(ctx, candidate)
		if err != nil {
			return candidate, failures, err
		}
		if len(failures) == 0 {
			if err := candidate.Validate(r); err != nil {
				failures = []Failure{{Kind: "schema", Detail: err.Error()}}
			} else {
				return candidate, nil, nil
			}
		}
		repairable := true
		messages := make([]string, 0, len(failures))
		for _, failure := range failures {
			switch failure.Kind {
			case "formatter", "schema", "lint":
			default:
				repairable = false
			}
			if len(failure.Detail) > 4096 {
				failure.Detail = failure.Detail[:4096]
			}
			messages = append(messages, failure.Kind+": "+failure.Detail)
		}
		if !repairable {
			return candidate, failures, errors.New("non-repairable evidence, sample or policy failure")
		}
		if attempt == 2 {
			return candidate, failures, errors.New("repair budget exhausted after three validation attempts")
		}
		next, err := model.Draft(ctx, DraftInput{RequestID: r.ID, Capability: r.Capability, Language: r.Language, Evidence: copyEvidence(r.Evidence), Failures: messages})
		if err != nil {
			return candidate, failures, err
		}
		if next.Schema != initial.Schema || next.RequestID != initial.RequestID || !reflect.DeepEqual(next.Citations, initial.Citations) || !reflect.DeepEqual(next.Uncertainty, initial.Uncertainty) {
			return candidate, failures, errors.New("repair attempted to change immutable request or citations")
		}
		candidate = next
	}
	return candidate, nil, errors.New("repair budget exhausted")
}
