package source

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestDecodeOriginalOffsets(t *testing.T) {
	for _, be := range []bool{false, true} {
		raw := []byte{0xff, 0xfe}
		var order binary.ByteOrder = binary.LittleEndian
		if be {
			raw = []byte{0xfe, 0xff}
			order = binary.BigEndian
		}
		for _, u := range utf16.Encode([]rune("é😀foo")) {
			b := make([]byte, 2)
			order.PutUint16(b, u)
			raw = append(raw, b...)
		}
		s, err := DecodeSource(raw)
		if err != nil {
			t.Fatal(err)
		}
		at, err := s.OriginalOffset(uint32(len("é😀")))
		if err != nil || at != 8 {
			t.Fatalf("offset=%d err=%v", at, err)
		}
	}
	for _, raw := range [][]byte{{0xff}, {0xff, 0xfe, 0}, {0xff, 0xfe, 0, 0xd8}} {
		if _, err := DecodeSource(raw); err == nil {
			t.Fatalf("accepted %x", raw)
		}
	}
}
