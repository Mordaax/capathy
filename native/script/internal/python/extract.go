// Package python extracts conservative python source evidence.
package python

import (
	"context"
	"github.com/mandiant/capa/native/script/internal/extract"
	"github.com/mandiant/capa/native/script/internal/protocol"
	"github.com/mandiant/capa/native/script/internal/source"
)

// Extract parses source without executing it.
func Extract(ctx context.Context, src source.Source) (protocol.Document, error) {
	return extract.Extract(ctx, src, "python")
}
