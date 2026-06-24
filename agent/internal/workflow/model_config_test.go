package workflow

import (
	"context"
	"iter"
	"testing"

	"google.golang.org/adk/v2/model"
	"google.golang.org/genai"
)

type requestCapture struct {
	name    string
	request *model.LLMRequest
}

func (m *requestCapture) Name() string { return m.name }
func (m *requestCapture) GenerateContent(ctx context.Context, request *model.LLMRequest, stream bool) iter.Seq2[*model.LLMResponse, error] {
	m.request = request
	return func(yield func(*model.LLMResponse, error) bool) {
		yield(&model.LLMResponse{Content: genai.NewContentFromText(`{"schema":1,"request_id":"demo","yaml":"rule: {}","citations":["e1"],"uncertainty":[]}`, genai.RoleModel)}, nil)
	}
}

func TestGemini3OmitsDeprecatedSamplingParameters(t *testing.T) {
	llm := &requestCapture{name: "gemini-3.8-flash"}
	adapter := GeminiModel{llm: llm, maxTokens: 8192}
	if _, err := adapter.Draft(context.Background(), DraftInput{RequestID: "demo"}); err != nil {
		t.Fatal(err)
	}
	if llm.request.Config.Temperature != nil || llm.request.Config.TopP != nil || llm.request.Config.TopK != nil {
		t.Fatal("Gemini 3 request includes deprecated sampling parameters")
	}
	if llm.request.Config.ThinkingConfig == nil || llm.request.Config.ThinkingConfig.ThinkingLevel != genai.ThinkingLevelLow {
		t.Fatal("simple rule drafting must use bounded low reasoning")
	}
	if llm.request.Config.ResponseMIMEType != "application/json" {
		t.Fatal("structured JSON output was not requested")
	}
}
