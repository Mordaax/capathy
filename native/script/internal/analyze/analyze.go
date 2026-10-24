// Package analyze owns safe language dispatch and source decoding.
package analyze

import (
	"context"
	"fmt"
	"github.com/mandiant/capa/native/script/internal/extract"
	"github.com/mandiant/capa/native/script/internal/protocol"
	"github.com/mandiant/capa/native/script/internal/source"
)

// Analyze parses one bounded script without executing input text.
func Analyze(ctx context.Context, language string, raw []byte) (protocol.Document, error) {
	if err := ctx.Err(); err != nil {
		return protocol.Document{}, err
	}
	src, err := source.DecodeSource(raw)
	if err != nil {
		return protocol.Document{}, fmt.Errorf("decode source: %w", err)
	}
	return extract.Extract(ctx, src, language)
}
