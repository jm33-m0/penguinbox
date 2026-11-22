package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestParseYARAOutput(t *testing.T) {
	output := "PenguinBox_ProcMaps /tmp/sample\n0x0:$a: /proc/self/maps\n0x10:$b: /proc/self/maps\n"
	matches := parseYARAOutput(output, "custom.yar")
	if len(matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(matches))
	}
	if matches[0]["rule"] != "PenguinBox_ProcMaps" {
		t.Fatalf("rule = %v", matches[0]["rule"])
	}
	stringsList, ok := matches[0]["strings"].([]map[string]any)
	if !ok || len(stringsList) != 2 {
		t.Fatalf("strings = %#v", matches[0]["strings"])
	}
	if stringsList[0]["identifier"] != "$a" || stringsList[0]["data"] != "/proc/self/maps" {
		t.Fatalf("string = %#v", stringsList[0])
	}
}

func TestAnalyzeELF(t *testing.T) {
	path, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	result := analyzeELF(path)
	if result.Kind != "elf" {
		t.Fatalf("kind = %q", result.Kind)
	}
	if result.Entry == "" || len(result.Segments) == 0 {
		t.Fatalf("ELF result = %+v", result)
	}
}

func TestInspectStrings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(path, []byte("prefix\x00/proc/self/maps\x00memfd_create\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := inspectStrings(path)
	matches, ok := result["suspicious"].([]map[string]any)
	if !ok || len(matches) < 2 {
		t.Fatalf("suspicious = %#v", result["suspicious"])
	}
}

func TestRunYARA(t *testing.T) {
	yara, err := exec.LookPath("yara")
	if err != nil {
		t.Skip("yara is not installed")
	}
	dir := t.TempDir()
	rule := "rule needle { strings: $a = \"needle\" ascii condition: $a }\n"
	if err := os.WriteFile(filepath.Join(dir, "custom.yar"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("a needle in a haystack"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := runYARA(context.Background(), yara, dir, target)
	matches, ok := report["matches"].([]map[string]any)
	if !ok || len(matches) != 1 {
		t.Fatalf("matches = %#v, errors = %#v", report["matches"], report["errors"])
	}
	if matches[0]["rule"] != "needle" {
		t.Fatalf("rule = %v", matches[0]["rule"])
	}
}

func TestHighestSeverity(t *testing.T) {
	got := highestSeverity([]finding{{Severity: "low"}, {Severity: "high"}, {Severity: "medium"}})
	if got != "high" {
		t.Fatalf("highestSeverity = %q", got)
	}
}
