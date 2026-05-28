// Package bash extracts conservative bash source evidence.
package bash

import (
	"context"
	"github.com/Mordaax/capathy/native/script/internal/extract"
	"github.com/Mordaax/capathy/native/script/internal/protocol"
	"github.com/Mordaax/capathy/native/script/internal/source"
)

// Extract parses source without executing it.
func Extract(ctx context.Context, src source.Source) (protocol.Document, error) {
	return extract.Extract(ctx, src, "bash")
}
