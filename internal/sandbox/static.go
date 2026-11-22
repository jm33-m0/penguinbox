package sandbox

import (
	"bytes"
	"cmp"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type finding struct {
	Severity  string `json:"severity"`
	Rule      string `json:"rule"`
	Indicator string `json:"indicator,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

type staticReport struct {
	ELF  staticResult   `json:"elf"`
	YARA map[string]any `json:"yara,omitempty"`
}

type staticResult struct {
	Kind      string           `json:"kind"`
	Format    map[string]any   `json:"format,omitempty"`
	Security  map[string]any   `json:"security,omitempty"`
	Sections  []map[string]any `json:"sections,omitempty"`
	Segments  []map[string]any `json:"segments,omitempty"`
	Strings   map[string]any   `json:"strings,omitempty"`
	Findings  []finding        `json:"findings,omitempty"`
	Severity  string           `json:"severity,omitempty"`
	Warnings  []string         `json:"warnings,omitempty"`
	ElfFile   string           `json:"elf_file,omitempty"`
	Entry     string           `json:"entry,omitempty"`
	Interp    string           `json:"interpreter,omitempty"`
	BuildID   string           `json:"build_id,omitempty"`
	Stripped  bool             `json:"stripped"`
	Static    bool             `json:"static"`
	RWX       []string         `json:"rwx_segments,omitempty"`
	ExecStack bool             `json:"executable_stack"`
}

// analyzeArtifact runs the ELF inspector and every static YARA rule file. The
// result is a map of analyzer blocks so a LitterBox client can treat each as
// its own static scanner.
func analyzeArtifact(ctx context.Context, path, yaraBinary, yaraRules string) staticReport {
	return staticReport{
		ELF:  analyzeELF(path),
		YARA: runYARA(ctx, yaraBinary, yaraRules, path),
	}
}

// analyzeELF inspects one artifact without executing it. ELF is the native
// Linux format; other containers get a low-confidence report instead of a
// parse failure.
func analyzeELF(path string) staticResult {
	file, err := elf.Open(path)
	if err != nil {
		return staticResult{
			Kind: "unknown",
			Findings: []finding{{
				Severity: "low", Rule: "file/not-elf",
				Detail: fmt.Sprintf("artifact is not an ELF image: %v", err),
			}},
			Severity: "low",
		}
	}
	defer file.Close()

	result := staticResult{
		Kind: "elf",
		Format: map[string]any{
			"class":   file.Class.String(),
			"machine": file.Machine.String(),
			"type":    file.Type.String(),
			"osabi":   file.OSABI.String(),
			"entry":   fmt.Sprintf("0x%x", file.Entry),
		},
		Entry: fmt.Sprintf("0x%x", file.Entry),
	}

	var (
		interp    string
		buildID   string
		rwx       []string
		execStack bool
	)
	for _, program := range file.Progs {
		flags := programFlags(program.Flags)
		if len(result.Segments) < 64 {
			result.Segments = append(result.Segments, map[string]any{
				"type":   program.Type.String(),
				"flags":  flags,
				"offset": program.Off,
				"vaddr":  fmt.Sprintf("0x%x", program.Vaddr),
				"filesz": program.Filesz,
				"memsz":  program.Memsz,
			})
		}
		switch program.Type {
		case elf.PT_INTERP:
			if data, err := io.ReadAll(io.LimitReader(program.Open(), 4096)); err == nil {
				interp = sanitizeText(strings.TrimRight(string(data), "\x00\n"))
			}
		case elf.PT_GNU_STACK:
			execStack = program.Flags&elf.PF_X != 0
		case elf.PT_LOAD:
			if program.Flags&elf.PF_R != 0 && program.Flags&elf.PF_W != 0 && program.Flags&elf.PF_X != 0 {
				rwx = append(rwx, fmt.Sprintf("%s at 0x%x", flags, program.Vaddr))
			}
		}
	}
	result.Interp = interp
	result.Static = interp == ""
	result.ExecStack = execStack
	result.RWX = rwx

	if section := file.Section(".note.gnu.build-id"); section != nil {
		if data, err := io.ReadAll(io.LimitReader(section.Open(), 4096)); err == nil {
			buildID = parseBuildID(data)
		}
	}
	result.BuildID = buildID
	result.Stripped = file.Section(".symtab") == nil

	for _, section := range file.Sections {
		if len(result.Sections) >= 64 {
			break
		}
		result.Sections = append(result.Sections, map[string]any{
			"name":  sanitizeText(section.Name),
			"type":  section.Type.String(),
			"flags": sectionFlags(section.Flags),
			"size":  section.Size,
			"addr":  fmt.Sprintf("0x%x", section.Addr),
		})
	}

	add := func(severity, rule, indicator, detail string) {
		result.Findings = append(result.Findings, finding{
			Severity: severity, Rule: rule, Indicator: indicator, Detail: detail,
		})
	}
	if len(rwx) > 0 {
		add("high", "elf/rwx-segment", strings.Join(rwx, ", "), "a loadable segment is readable, writable, and executable")
	}
	if execStack {
		add("high", "elf/executable-stack", "", "PT_GNU_STACK requests an executable stack")
	}
	if result.Static {
		add("medium", "elf/static", "", "statically linked image; no PT_INTERP")
	}
	if result.Stripped {
		add("low", "elf/stripped", "", "no .symtab; symbols are stripped")
	}
	if buildID == "" {
		add("low", "elf/no-build-id", "", "no .note.gnu.build-id note")
	}
	if interp != "" && strings.Contains(interp, "/tmp/") {
		add("high", "elf/interpreter-tmp", interp, "dynamic loader is outside a system path")
	}

	stringInfo := inspectStrings(path)
	result.Strings = stringInfo
	if matches, ok := stringInfo["suspicious"].([]map[string]any); ok {
		for _, match := range matches {
			token, _ := match["token"].(string)
			severity := "medium"
			switch token {
			case "/proc/self/maps", "memfd_create", "ptrace", "process_vm_readv", "process_vm_writev", "LD_PRELOAD":
				severity = "high"
			}
			add(severity, "elf/string", token, "artifact contains a high-signal technique string")
		}
	}
	if len(result.Findings) > 32 {
		result.Findings = result.Findings[:32]
	}
	result.Severity = highestSeverity(result.Findings)
	return result
}

func programFlags(flags elf.ProgFlag) string {
	var out strings.Builder
	if flags&elf.PF_R != 0 {
		out.WriteByte('R')
	}
	if flags&elf.PF_W != 0 {
		out.WriteByte('W')
	}
	if flags&elf.PF_X != 0 {
		out.WriteByte('X')
	}
	return out.String()
}

func sectionFlags(flags elf.SectionFlag) string {
	var out strings.Builder
	if flags&elf.SHF_ALLOC != 0 {
		out.WriteByte('A')
	}
	if flags&elf.SHF_WRITE != 0 {
		out.WriteByte('W')
	}
	if flags&elf.SHF_EXECINSTR != 0 {
		out.WriteByte('X')
	}
	if flags&elf.SHF_TLS != 0 {
		out.WriteByte('T')
	}
	if out.Len() == 0 {
		return "-"
	}
	return out.String()
}

func parseBuildID(data []byte) string {
	if len(data) < 16 {
		return ""
	}
	namesz := binary.LittleEndian.Uint32(data[0:4])
	descsz := binary.LittleEndian.Uint32(data[4:8])
	noteType := binary.LittleEndian.Uint32(data[8:12])
	if noteType != 3 {
		return ""
	}
	nameEnd := 12 + int(namesz)
	nameEnd = (nameEnd + 3) &^ 3
	descEnd := nameEnd + int(descsz)
	if nameEnd < 0 || descEnd > len(data) || descEnd < nameEnd {
		return ""
	}
	return hex.EncodeToString(data[nameEnd:descEnd])
}

var suspiciousTokens = []string{
	"/proc/self/maps",
	"/proc/self/status",
	"memfd_create",
	"ptrace",
	"process_vm_readv",
	"process_vm_writev",
	"LD_PRELOAD",
	"dlopen",
	"dlsym",
	"mprotect",
	"prctl",
	"execve",
	"process_vm",
	"setns",
	"unshare",
	"bpf",
	"init_module",
	"finit_module",
	"pivot_root",
	"http://",
	"https://",
}

func inspectStrings(path string) map[string]any {
	result := map[string]any{
		"total":      0,
		"printable":  0,
		"suspicious": []map[string]any{},
	}
	file, err := os.Open(path)
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	defer file.Close()
	const maxInspect = 64 << 20
	data, err := io.ReadAll(io.LimitReader(file, maxInspect+1))
	if err != nil {
		result["error"] = err.Error()
		return result
	}
	if len(data) > maxInspect {
		data = data[:maxInspect]
		result["truncated"] = true
	}
	stringsFound, printable := extractPrintable(data)
	result["total"] = len(stringsFound)
	result["printable"] = printable

	var matches []map[string]any
	for _, token := range suspiciousTokens {
		if count := bytes.Count(data, []byte(token)); count > 0 {
			matches = append(matches, map[string]any{"token": token, "count": count})
		}
	}
	slices.SortFunc(matches, func(a, b map[string]any) int {
		return cmp.Compare(a["token"].(string), b["token"].(string))
	})
	if len(matches) > 24 {
		matches = matches[:24]
	}
	result["suspicious"] = matches
	return result
}

func extractPrintable(data []byte) ([]string, int) {
	var out []string
	start := -1
	printable := 0
	for index, value := range data {
		if value >= 0x20 && value <= 0x7e {
			printable++
			if start < 0 {
				start = index
			}
			continue
		}
		if start >= 0 && index-start >= 4 {
			out = append(out, string(data[start:index]))
			if len(out) >= 4096 {
				return out, printable
			}
		}
		start = -1
	}
	if start >= 0 && len(data)-start >= 4 && len(out) < 4096 {
		out = append(out, string(data[start:]))
	}
	return out, printable
}

func highestSeverity(findings []finding) string {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	best := ""
	bestRank := 0
	for _, item := range findings {
		if value := rank[item.Severity]; value > bestRank {
			best = item.Severity
			bestRank = value
		}
	}
	return best
}

// runYARA executes every rule file in the configured directory against the
// artifact. YARA exit code 1 means "no match", not an error.
func runYARA(ctx context.Context, binary, rulesDir, target string) map[string]any {
	report := map[string]any{
		"engine":   "yara",
		"dir":      rulesDir,
		"files":    []string{},
		"matches":  []map[string]any{},
		"errors":   []string{},
		"severity": "low",
	}
	names, err := listFiles(rulesDir, ".yar", ".yara")
	if err != nil {
		report["errors"] = []string{fmt.Sprintf("read rules directory: %v", err)}
		return report
	}
	files := make([]string, 0, len(names))
	for _, name := range names {
		files = append(files, filepath.Join(rulesDir, name))
	}

	errorsList := []string{}
	if len(files) > 64 {
		files = files[:64]
		errorsList = append(errorsList, "rule file list truncated to 64")
	}
	report["files"] = files

	matches := []map[string]any{}
	for _, ruleFile := range files {
		yaraCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		outBuf := &limitedBuffer{limit: 4 << 20}
		cmd := exec.CommandContext(yaraCtx, binary, "-a", "30", "-w", "-s", ruleFile, target)
		cmd.Stdout = outBuf
		cmd.Stderr = outBuf
		runErr := cmd.Run()
		cancel()
		if runErr != nil {
			var exitErr *exec.ExitError
			if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != 1 {
				errorsList = append(errorsList, fmt.Sprintf("%s: %v", filepath.Base(ruleFile), runErr))
			}
		}
		matches = append(matches, parseYARAOutput(outBuf.String(), filepath.Base(ruleFile))...)
		if len(matches) >= 100 {
			matches = matches[:100]
			errorsList = append(errorsList, "match list truncated to 100")
			break
		}
	}
	report["matches"] = matches
	report["errors"] = errorsList
	severity := "low"
	for _, match := range matches {
		if value, _ := match["meta"].(map[string]any); value != nil && value["severity"] == "high" {
			severity = "high"
			break
		}
	}
	report["severity"] = severity
	return report
}

func parseYARAOutput(output, ruleFile string) []map[string]any {
	var matches []map[string]any
	var current map[string]any
	for _, rawLine := range strings.Split(output, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		if line == "" {
			continue
		}
		if current != nil && strings.Contains(line, ":$") && (strings.HasPrefix(strings.TrimSpace(line), "0x") || line[0] == ' ' || line[0] == '\t') {
			_, rest, ok := strings.Cut(strings.TrimSpace(line), ":$")
			if !ok {
				continue
			}
			identifier, value, ok := strings.Cut(rest, ":")
			if !ok {
				continue
			}
			stringsList, _ := current["strings"].([]map[string]any)
			stringsList = append(stringsList, map[string]any{
				"identifier": "$" + sanitizeText(strings.TrimSpace(identifier)),
				"data":       sanitizeText(strings.TrimSpace(value)),
			})
			current["strings"] = stringsList
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			current = map[string]any{
				"rule":    sanitizeText(fields[0]),
				"file":    ruleFile,
				"meta":    map[string]any{"severity": "high", "source": "custom-yara"},
				"strings": []map[string]any{},
			}
			matches = append(matches, current)
		}
	}
	return matches
}
