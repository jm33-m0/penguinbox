package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// limitedBuffer captures up to limit bytes and discards the rest so noisy
// subprocess output cannot exhaust service memory.
type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		return len(p), nil
	}
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		_, _ = b.buf.Write(p[:min(len(p), remaining)])
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}

func sanitizeText(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 0x20 && r <= 0x7e {
			return r
		}
		return -1
	}, value)
}

func sanitizeMultiline(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || (r >= 0x20 && r <= 0x7e) {
			return r
		}
		return -1
	}, value)
}

// listFiles returns sorted base filenames in dir matching any of the given
// lowercase extensions.
func listFiles(dir string, extensions ...string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if slices.Contains(extensions, strings.ToLower(filepath.Ext(entry.Name()))) {
			out = append(out, entry.Name())
		}
	}
	slices.Sort(out)
	return out, nil
}
