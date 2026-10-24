// Package source decodes script text while retaining original byte locations.
package source

import (
	"encoding/binary"
	"errors"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxInput bounds a single script.
const MaxInput = 16 << 20

// Source contains UTF-8 text and its original-byte offset map.
type Source struct {
	Raw     []byte
	Text    []byte
	offsets []uint32
}

// OriginalOffset maps a UTF-8 byte boundary to the original file offset.
func (s Source) OriginalOffset(offset uint32) (uint32, error) {
	if int(offset) >= len(s.offsets) {
		return 0, errors.New("source offset out of bounds")
	}
	return s.offsets[offset], nil
}

// DecodeSource accepts UTF-8 and BOM marked UTF-16LE/BE, rejecting malformed text.
func DecodeSource(raw []byte) (Source, error) {
	s := Source{Raw: raw}
	if len(raw) > MaxInput {
		return s, errors.New("input exceeds 16 MiB")
	}
	start := 0
	if len(raw) >= 3 && string(raw[:3]) == "\xef\xbb\xbf" {
		start = 3
	}
	if len(raw) >= 2 && (string(raw[:2]) == "\xff\xfe" || string(raw[:2]) == "\xfe\xff") {
		var order binary.ByteOrder = binary.LittleEndian
		if raw[0] == 0xfe {
			order = binary.BigEndian
		}
		if len(raw)%2 != 0 {
			return s, errors.New("truncated UTF-16")
		}
		for i := 2; i < len(raw); {
			begin := i
			u := order.Uint16(raw[i : i+2])
			i += 2
			r := rune(u)
			if utf16.IsSurrogate(r) {
				if u < 0xd800 || u > 0xdbff || i+2 > len(raw) {
					return s, errors.New("invalid UTF-16 surrogate")
				}
				v := order.Uint16(raw[i : i+2])
				if v < 0xdc00 || v > 0xdfff {
					return s, errors.New("invalid UTF-16 surrogate")
				}
				r = utf16.DecodeRune(r, rune(v))
				i += 2
			}
			b := []byte(string(r))
			s.Text = append(s.Text, b...)
			for range b {
				s.offsets = append(s.offsets, uint32(begin))
			}
		}
		s.offsets = append(s.offsets, uint32(len(raw)))
		return s, nil
	}
	if !utf8.Valid(raw[start:]) {
		return s, errors.New("invalid UTF-8")
	}
	s.Text = raw[start:]
	for i := start; i <= len(raw); i++ {
		s.offsets = append(s.offsets, uint32(i))
	}
	return s, nil
}
