package amnezia

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

var payloadTagPattern = regexp.MustCompile(`<([^>]*)>`)

// BuildTaggedPayload implements the official send_payload subset: <b 0xHEX>
// and <r N>. Unknown/malformed tags return an error rather than being silently
// ignored. A nil random source uses crypto/rand.Reader.
func BuildTaggedPayload(spec string, random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	var result []byte
	for _, match := range payloadTagPattern.FindAllStringSubmatch(spec, -1) {
		parts := strings.Fields(match[1])
		if len(parts) < 2 {
			return nil, fmt.Errorf("amnezia: malformed payload tag %q", match[0])
		}
		switch strings.ToLower(parts[0]) {
		case "b":
			raw := strings.TrimPrefix(strings.TrimPrefix(parts[1], "0x"), "0X")
			decoded, err := hex.DecodeString(raw)
			if err != nil {
				return nil, fmt.Errorf("amnezia: payload hex: %w", err)
			}
			result = append(result, decoded...)
		case "r":
			count, err := strconv.Atoi(parts[1])
			if err != nil || count < 0 || count > 1<<20 {
				return nil, fmt.Errorf("amnezia: invalid random payload size %q", parts[1])
			}
			start := len(result)
			result = append(result, make([]byte, count)...)
			if _, err := io.ReadFull(random, result[start:]); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("amnezia: unsupported payload tag %q", parts[0])
		}
	}
	return result, nil
}
