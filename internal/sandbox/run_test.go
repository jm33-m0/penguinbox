package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFalcoFiltersContainer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "falco.json")
	content := `{"rule":"custom","priority":"Warning","output_fields":{"container.id":"abcdef123456"}}
{"rule":"other","priority":"Warning","output_fields":{"container.id":"ffffffffffff"}}
{"rule":"host","priority":"Warning","output_fields":{"container.id":"host"}}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	events, total, err := readFalco(path, 0, "abcdef1234567890", 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(events) != 1 {
		t.Fatalf("total=%d events=%d", total, len(events))
	}
	var event map[string]any
	if err := json.Unmarshal(events[0], &event); err != nil {
		t.Fatal(err)
	}
	if event["collector"] != "falco" || event["rule"] != "custom" {
		t.Fatalf("event = %#v", event)
	}
}

func TestContainerIDFromOutput(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got := containerIDFromOutput("warning: something\n" + id + "\n")
	if got != id {
		t.Fatalf("container id = %q, want %q", got, id)
	}
	if containerIDFromOutput("not an id") != "" {
		t.Fatal("expected empty container id")
	}
}

func TestFalcoMatches(t *testing.T) {
	object := map[string]any{"output_fields": map[string]any{"container.id": "abcdef123456"}}
	if !falcoMatches(object, "abcdef1234567890") {
		t.Fatal("expected container match")
	}
	if falcoMatches(object, "ffffffffffffffff") {
		t.Fatal("unexpected container match")
	}
	if falcoMatches(object, "") {
		t.Fatal("empty container id must not match")
	}
	shortObj := map[string]any{"output_fields": map[string]any{"container.id": "a"}}
	if falcoMatches(shortObj, "abcdef1234567890") {
		t.Fatal("short container id must not match")
	}
}

func TestLimitedBuffer(t *testing.T) {
	buf := &limitedBuffer{limit: 5}
	n, err := buf.Write([]byte("hello world"))
	if err != nil || n != 11 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if buf.String() != "hello" {
		t.Fatalf("String = %q, want hello", buf.String())
	}
}

func TestComputeRisk(t *testing.T) {
	static := staticReport{
		ELF:  staticResult{Findings: []finding{{Severity: "high", Rule: "elf/rwx-segment"}}},
		YARA: map[string]any{"matches": []any{map[string]any{"rule": "custom"}}},
	}
	dynamic := dynamicResult{Findings: eventBundle{Events: []json.RawMessage{
		json.RawMessage(`{"collector":"falco","priority":"Warning"}`),
	}}}
	risk := computeRisk(static, dynamic)
	if risk.Score <= 0 || risk.Level == "none" {
		t.Fatalf("risk = %+v", risk)
	}
	if len(risk.Factors) == 0 {
		t.Fatal("risk has no factors")
	}
}

func TestHostAliasArgs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host-internal")
	if err := os.WriteFile(path, []byte("169.254.1.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{HostAliasFile: path}}
	got := strings.Join(s.hostAliasArgs(), " ")
	want := "--add-host host.containers.internal:169.254.1.2 --add-host host.docker.internal:169.254.1.2"
	if got != want {
		t.Fatalf("args = %q, want %q", got, want)
	}

	if err := os.WriteFile(path, []byte("not an address\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if args := s.hostAliasArgs(); args != nil {
		t.Fatalf("invalid address produced args %v", args)
	}

	if args := (&Server{cfg: Config{HostAliasFile: filepath.Join(dir, "missing")}}).hostAliasArgs(); args != nil {
		t.Fatalf("missing file produced args %v", args)
	}
}

func TestTailStripsControls(t *testing.T) {
	got := tail("hello\x00\x1b[31mworld", 100)
	if got != "hello[31mworld" {
		t.Fatalf("tail = %q", got)
	}
}
