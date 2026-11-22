package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type runMeta struct {
	RunID         string    `json:"run_id"`
	MD5           string    `json:"md5"`
	SHA256        string    `json:"sha256"`
	Name          string    `json:"name"`
	Artifact      string    `json:"artifact"`
	Image         string    `json:"image"`
	ContainerID   string    `json:"container_id,omitempty"`
	ContainerName string    `json:"container_name,omitempty"`
	PayloadPID    int64     `json:"payload_pid,omitempty"`
	ExitCode      int       `json:"exit_code"`
	TimedOut      bool      `json:"timed_out"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	DurationMS    int64     `json:"duration_ms"`
	Warnings      []string  `json:"warnings,omitempty"`
	LogTail       string    `json:"log_tail,omitempty"`
	Error         string    `json:"error,omitempty"`
}

type collectorCoverage struct {
	Events int    `json:"events,omitempty"`
	Alerts int    `json:"alerts,omitempty"`
	Error  string `json:"error,omitempty"`
}

type coverage struct {
	Tracee   collectorCoverage `json:"tracee"`
	Falco    collectorCoverage `json:"falco"`
	Expected []string          `json:"expected,omitempty"`
	Missing  []string          `json:"missing,omitempty"`
}

type eventBundle struct {
	Events []json.RawMessage `json:"events"`
}

type dynamicResult struct {
	Run      runMeta     `json:"run"`
	Findings eventBundle `json:"findings"`
	Coverage coverage    `json:"coverage"`
}

func (s *Server) runDynamic(ctx context.Context, info upload) (dynamicResult, error) {
	select {
	case s.runGate <- struct{}{}:
		defer func() { <-s.runGate }()
	case <-ctx.Done():
		return dynamicResult{}, ctx.Err()
	}

	started := time.Now().UTC()
	runID := started.Format("20060102T150405Z") + "-" + info.MD5[:8]
	result := dynamicResult{
		Run: runMeta{
			RunID: runID, MD5: info.MD5, SHA256: info.SHA256, Name: info.Name,
			Artifact: info.Path, Image: s.cfg.Image, StartedAt: started,
			Warnings: []string{},
		},
		Findings: eventBundle{Events: []json.RawMessage{}},
		Coverage: coverage{Expected: []string{"tracee", "falco"}},
	}
	warn := func(format string, args ...any) {
		result.Run.Warnings = append(result.Run.Warnings, fmt.Sprintf(format, args...))
	}

	var traceSeq uint64
	traceReady := false
	if s.trace == nil {
		result.Coverage.Tracee.Error = "tracee collector is not running"
		result.Coverage.Missing = append(result.Coverage.Missing, "tracee")
	} else if err := s.trace.waitReady(ctx, 120*time.Second); err != nil {
		result.Coverage.Tracee.Error = err.Error()
		result.Coverage.Missing = append(result.Coverage.Missing, "tracee")
		warn("tracee unavailable: %v", err)
	} else {
		traceReady = true
		traceSeq = s.trace.sequence()
	}

	falcoOffset, falcoOffsetErr := fileSize(s.cfg.FalcoLog)
	if falcoOffsetErr != nil {
		warn("falco log unavailable before run: %v", falcoOffsetErr)
		falcoOffset = 0
	}

	containerID, payloadPID, exitCode, timedOut, logTail, runErr := s.detonate(ctx, info, runID)
	result.Run.ContainerID = containerID
	result.Run.ContainerName = containerName(runID)
	result.Run.PayloadPID = payloadPID
	result.Run.LogTail = logTail
	result.Run.ExitCode = exitCode
	result.Run.TimedOut = timedOut
	if runErr != nil {
		result.Run.Error = runErr.Error()
		warn("payload failed to run: %v", runErr)
	}

	if traceReady {
		traceEvents, total := s.trace.since(traceSeq, containerID, s.cfg.MaxEvents)
		result.Coverage.Tracee.Events = total
		result.Findings.Events = append(result.Findings.Events, traceEvents...)
		if total == 0 {
			result.Coverage.Missing = append(result.Coverage.Missing, "tracee")
		}
		if total > len(traceEvents) {
			warn("tracee events truncated from %d to %d", total, len(traceEvents))
		}
	} else if s.trace != nil {
		result.Coverage.Tracee.Error = "tracee was not ready for this run"
	}

	falcoEvents, total, err := readFalco(s.cfg.FalcoLog, falcoOffset, containerID, s.cfg.MaxEvents)
	if err != nil {
		result.Coverage.Falco.Error = err.Error()
		result.Coverage.Missing = append(result.Coverage.Missing, "falco")
		warn("falco capture: %v", err)
	} else {
		result.Coverage.Falco.Alerts = total
		result.Findings.Events = append(result.Findings.Events, falcoEvents...)
		if total == 0 {
			result.Coverage.Missing = append(result.Coverage.Missing, "falco")
		}
		if total > len(falcoEvents) {
			warn("falco alerts truncated from %d to %d", total, len(falcoEvents))
		}
	}

	if len(result.Findings.Events) > s.cfg.MaxEvents {
		result.Findings.Events = result.Findings.Events[:s.cfg.MaxEvents]
		warn("combined telemetry truncated to %d events", s.cfg.MaxEvents)
	}

	result.Run.FinishedAt = time.Now().UTC()
	result.Run.DurationMS = result.Run.FinishedAt.Sub(started).Milliseconds()
	if err := s.store.saveJSON(info.MD5, "dynamic", result); err != nil {
		return dynamicResult{}, err
	}
	s.store.removeResult(info.MD5, "risk")
	return result, nil
}

func (s *Server) detonate(ctx context.Context, info upload, runID string) (string, int64, int, bool, string, error) {
	args := []string{
		"run", "-d", "--name", containerName(runID),
		"--label", "penguinbox.run=" + runID,
		"--cap-drop=ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
		"--pids-limit", "256",
		"--memory", "512m",
		"--memory-swap", "512m",
		"--cpus", "1",
		"--log-opt", "max-size=1m",
	}
	if networkMode := strings.TrimSpace(s.cfg.PayloadNetwork); networkMode != "" {
		args = append(args, "--network", networkMode)
	}
	args = append(args, s.hostAliasArgs()...)
	args = append(args,
		"-v", info.Path+":/payload:ro",
		"--entrypoint", "/payload",
		s.cfg.Image,
	)

	output, err := exec.CommandContext(ctx, s.cfg.Podman, args...).CombinedOutput()
	if err != nil {
		return "", 0, -1, false, tail(string(output), 8192), fmt.Errorf("podman run: %w: %s", err, strings.TrimSpace(string(output)))
	}
	containerID := containerIDFromOutput(string(output))
	if len(containerID) < 12 {
		return "", 0, -1, false, "", fmt.Errorf("podman run returned no container id: %s", strings.TrimSpace(string(output)))
	}
	payloadPID := s.podmanPID(containerID)

	waitCtx, cancel := context.WithTimeout(ctx, s.cfg.DetonateTimeout)
	defer cancel()
	waitOutput, waitErr := exec.CommandContext(waitCtx, s.cfg.Podman, "wait", containerID).CombinedOutput()
	timedOut := errors.Is(waitCtx.Err(), context.DeadlineExceeded)
	if timedOut || waitCtx.Err() != nil {
		_ = exec.Command(s.cfg.Podman, "kill", containerID).Run()
	}
	exitCode := -1
	if !timedOut && waitErr == nil {
		if parsed, parseErr := strconv.Atoi(strings.TrimSpace(string(waitOutput))); parseErr == nil {
			exitCode = parsed
		}
	}

	logCtx, logCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer logCancel()
	logBuf := &limitedBuffer{limit: 64 << 10}
	logCmd := exec.CommandContext(logCtx, s.cfg.Podman, "logs", "--tail", "200", containerID)
	logCmd.Stdout = logBuf
	logCmd.Stderr = logBuf
	_ = logCmd.Run()
	logTail := tail(logBuf.String(), 8192)
	_ = exec.Command(s.cfg.Podman, "rm", "-f", containerID).Run()

	if waitErr != nil && !timedOut {
		return containerID, payloadPID, exitCode, false, logTail, fmt.Errorf("wait for payload: %w", waitErr)
	}
	return containerID, payloadPID, exitCode, timedOut, logTail, nil
}

// hostAliasArgs points host.containers.internal and host.docker.internal at the
// Podman host that runs the sandbox container. Podman inside the guest would
// otherwise advertise its own bridge gateway, so a payload configured for the
// operator host would reach the guest instead of the host.
func (s *Server) hostAliasArgs() []string {
	if s.cfg.HostAliasFile == "" {
		return nil
	}
	data, err := os.ReadFile(s.cfg.HostAliasFile)
	if err != nil {
		return nil
	}
	addr := strings.TrimSpace(string(data))
	if len(addr) > 64 {
		return nil
	}
	ip := net.ParseIP(addr)
	if ip == nil || ip.To4() == nil {
		return nil
	}
	args := make([]string, 0, 4)
	for _, name := range []string{"host.containers.internal", "host.docker.internal"} {
		args = append(args, "--add-host", name+":"+addr)
	}
	return args
}

func (s *Server) podmanPID(containerID string) int64 {
	if containerID == "" {
		return 0
	}
	output, err := exec.Command(s.cfg.Podman, "inspect", "-f", "{{.State.Pid}}", containerID).Output()
	if err != nil {
		return 0
	}
	value, _ := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	return value
}

func readFalco(path string, offset int64, containerID string, limit int) ([]json.RawMessage, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	if offset > 0 {
		if info, statErr := file.Stat(); statErr == nil && offset <= info.Size() {
			if _, err := file.Seek(offset, 0); err != nil {
				return nil, 0, err
			}
		}
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	var events []json.RawMessage
	total := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var object map[string]any
		if err := json.Unmarshal([]byte(line), &object); err != nil {
			continue
		}
		if !falcoMatches(object, containerID) {
			continue
		}
		total++
		if len(events) >= limit {
			continue
		}
		object["collector"] = "falco"
		encoded, err := json.Marshal(object)
		if err != nil {
			continue
		}
		events = append(events, encoded)
	}
	return events, total, scanner.Err()
}

func falcoMatches(object map[string]any, containerID string) bool {
	if containerID == "" {
		return false
	}
	short := containerID[:min(12, len(containerID))]
	if fields, ok := object["output_fields"].(map[string]any); ok {
		if id, ok := fields["container.id"].(string); ok && len(id) >= 12 {
			return id == containerID || id == short || strings.HasPrefix(containerID, id) || strings.HasPrefix(id, short)
		}
	}
	output, _ := object["output"].(string)
	return output != "" && len(short) >= 12 && strings.Contains(output, short)
}

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func containerName(runID string) string {
	name := "penguinbox-" + strings.ToLower(runID)
	return name[:min(60, len(name))]
}

func containerIDFromOutput(value string) string {
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 12 {
			continue
		}
		valid := true
		for _, r := range line {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				valid = false
				break
			}
		}
		if valid {
			return line
		}
	}
	return ""
}

func tail(value string, limit int) string {
	value = sanitizeMultiline(value)
	if len(value) <= limit {
		return value
	}
	return value[len(value)-limit:]
}
