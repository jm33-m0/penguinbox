package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// traceBuffer keeps the most recent container-scoped Tracee events in memory.
// The collector runs for the service lifetime, so a detonation never pays the
// eBPF initialization cost.
type traceBuffer struct {
	mu       sync.RWMutex
	items    []collectedEvent
	start    int
	size     int
	capacity int
	next     uint64
}

type collectedEvent struct {
	seq         uint64
	containerID string
	raw         json.RawMessage
}

// DefaultTraceeEvents selects the syscall and LSM events the EDR profile
// grades. The default set already includes memfd_create, ptrace, setns,
// process_vm_*, chmod, init_module, exec, and LSM socket hooks; these explicit
// additions cover file, memory, mount, namespace, BPF, kexec, and module
// operations that the findings reader uses.
const DefaultTraceeEvents = "default,openat,openat2,mmap,mprotect,connect,listen,execve,execveat,unlink,unlinkat,rename,renameat,renameat2,truncate,ftruncate,mount,umount2,unshare,bpf,kexec_load,kexec_file_load,delete_module"

func newTraceBuffer(capacity int) *traceBuffer {
	capacity = max(capacity, 1)
	return &traceBuffer{
		items:    make([]collectedEvent, capacity),
		capacity: capacity,
		next:     1,
	}
}

func (b *traceBuffer) add(containerID string, raw []byte) {
	if containerID == "" || len(raw) == 0 || raw[0] != '{' {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	event := collectedEvent{seq: b.next, containerID: containerID, raw: append(json.RawMessage(nil), raw...)}
	b.next++
	if b.size < b.capacity {
		b.items[(b.start+b.size)%b.capacity] = event
		b.size++
		return
	}
	b.items[b.start] = event
	b.start = (b.start + 1) % b.capacity
}

func (b *traceBuffer) sequence() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.next
}

func (b *traceBuffer) since(seq uint64, containerID string, limit int) ([]json.RawMessage, int) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	total := 0
	events := make([]json.RawMessage, 0, min(limit, b.size))
	for index := range b.size {
		event := b.items[(b.start+index)%b.capacity]
		if event.seq < seq {
			continue
		}
		if containerID != "" && event.containerID != containerID {
			continue
		}
		total++
		if len(events) < limit {
			events = append(events, tagTracee(event.raw))
		}
	}
	return events, total
}

type traceCollector struct {
	cfg     Config
	buffer  *traceBuffer
	logPath string

	once     sync.Once
	ready    chan struct{}
	readyErr error
	cmd      *exec.Cmd
}

func newTraceCollector(cfg Config) *traceCollector {
	collector := &traceCollector{
		cfg:     cfg,
		buffer:  newTraceBuffer(cfg.MaxEvents),
		logPath: filepath.Join(filepath.Dir(cfg.FalcoLog), "tracee.log"),
		ready:   make(chan struct{}),
	}
	if err := collector.start(); err != nil {
		collector.finish(err)
	}
	return collector
}

func (c *traceCollector) start() error {
	if _, err := os.Stat(c.cfg.Tracee); err != nil {
		return fmt.Errorf("tracee binary: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(c.logPath), 0o755); err != nil {
		return fmt.Errorf("create tracee log directory: %w", err)
	}
	events := strings.TrimSpace(c.cfg.TraceeEvents)
	if events == "" {
		events = DefaultTraceeEvents
	}
	args := []string{
		"--output", "json",
		"--output", "option:parse-arguments,exec-hash",
		"--events", events,
		"--log", "info",
	}
	if _, err := os.Stat("/run/podman/podman.sock"); err == nil {
		args = append(args, "--containers", "enrich=true", "--containers", "sockets.podman=/run/podman/podman.sock")
	}
	cmd := exec.Command(c.cfg.Tracee, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("tracee stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("tracee stderr: %w", err)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tracee: %w", err)
	}
	c.cmd = cmd
	go c.readEvents(stdout)
	go c.readLog(stderr)
	go func() {
		err := cmd.Wait()
		c.finish(fmt.Errorf("tracee exited: %v", err))
	}()
	return nil
}

func (c *traceCollector) readEvents(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var meta struct {
			ContainerID string `json:"containerId"`
		}
		if err := json.Unmarshal([]byte(line), &meta); err != nil {
			continue
		}
		c.buffer.add(meta.ContainerID, []byte(line))
	}
	c.finish(fmt.Errorf("tracee stdout: %v", scanner.Err()))
}

func (c *traceCollector) readLog(reader io.Reader) {
	file, err := os.OpenFile(c.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err == nil {
		defer file.Close()
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if file != nil {
			_, _ = file.WriteString(line + "\n")
		}
		if strings.Contains(line, "enabled cap") || strings.Contains(line, "Tracing started") {
			c.finish(nil)
		}
	}
}

func (c *traceCollector) finish(err error) {
	c.once.Do(func() {
		c.readyErr = err
		close(c.ready)
	})
}

func (c *traceCollector) waitReady(ctx context.Context, timeout time.Duration) error {
	select {
	case <-c.ready:
		return c.readyErr
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(timeout):
		return fmt.Errorf("tracee did not become ready within %s", timeout)
	}
}

func tagTracee(raw json.RawMessage) json.RawMessage {
	if len(raw) < 2 || raw[0] != '{' {
		return raw
	}
	tagged := make([]byte, 0, len(raw)+24)
	tagged = append(tagged, '{')
	tagged = append(tagged, `"collector":"tracee",`...)
	tagged = append(tagged, raw[1:]...)
	return tagged
}

func (c *traceCollector) sequence() uint64 {
	return c.buffer.sequence()
}

func (c *traceCollector) since(seq uint64, containerID string, limit int) ([]json.RawMessage, int) {
	return c.buffer.since(seq, containerID, limit)
}

func (c *traceCollector) close() {
	if c == nil || c.cmd == nil || c.cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-c.cmd.Process.Pid, syscall.SIGTERM)
}
