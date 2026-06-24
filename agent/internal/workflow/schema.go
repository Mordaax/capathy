package workflow

// proposalSchema constrains the response envelope and binds citations to input evidence.
func proposalSchema(input DraftInput) map[string]any {
	citation := map[string]any{"type": "string"}
	ids := []string{}
	for _, item := range input.Evidence {
		ids = append(ids, item.ID)
	}
	if len(ids) > 0 {
		citation["enum"] = ids
	}
	return map[string]any{
		"type": "object", "additionalProperties": false,
		"required": []string{"schema", "request_id", "yaml", "citations", "uncertainty"},
		"properties": map[string]any{
			"schema":      map[string]any{"type": "integer", "enum": []int{1}},
			"request_id":  map[string]any{"type": "string", "enum": []string{input.RequestID}},
			"yaml":        map[string]any{"type": "string", "description": "A complete capa YAML document starting with rule:, with meta and features nested under rule. Not Markdown."},
			"citations":   map[string]any{"type": "array", "items": citation},
			"uncertainty": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
	}
}
