//go:build e2e

// Package e2e drives a real PenguinBox guest and exercises the
// LitterBox-compatible API, the static YARA rules, and the behavioral Falco
// rules. Run it with:
//
//	go test -tags=e2e ./test/e2e -v -timeout 30m
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	containerName = "penguinbox"
	hostSSHPort   = "2223"
	hostAPIPort   = "1338"
)

type scanner struct {
	Group   string `json:"group"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Enabled bool   `json:"enabled"`
	Exists  bool   `json:"exists"`
}

type health struct {
	Scanners struct {
		Rows []scanner `json:"rows"`
	} `json:"scanners"`
	Rules struct {
		Static struct {
			Dir   string   `json:"dir"`
			Files []string `json:"files"`
		} `json:"static"`
		Behavioral struct {
			Dir    string   `json:"dir"`
			Files  []string `json:"files"`
			Engine string   `json:"engine"`
		} `json:"behavioral"`
	} `json:"rules"`
}

type uploadResponse struct {
	FileInfo struct {
		MD5          string `json:"md5"`
		SHA256       string `json:"sha256"`
		Size         int64  `json:"size"`
		OriginalName string `json:"original_name"`
		DetectedType struct {
			Family string `json:"family"`
			Type   string `json:"type"`
		} `json:"detected_type"`
	} `json:"file_info"`
}

type analyzeResponse struct {
	Status  string                     `json:"status"`
	Error   string                     `json:"error"`
	Results map[string]json.RawMessage `json:"results"`
}

type staticYARA struct {
	Matches []struct {
		Rule    string `json:"rule"`
		File    string `json:"file"`
		Strings []struct {
			Identifier string `json:"identifier"`
			Data       string `json:"data"`
		} `json:"strings"`
	} `json:"matches"`
	Errors []string `json:"errors"`
}

type dynamicResult struct {
	Run struct {
		ExitCode    int      `json:"exit_code"`
		TimedOut    bool     `json:"timed_out"`
		ContainerID string   `json:"container_id"`
		Error       string   `json:"error"`
		Warnings    []string `json:"warnings"`
	} `json:"run"`
	Findings struct {
		Events []json.RawMessage `json:"events"`
	} `json:"findings"`
	Coverage struct {
		Tracee struct {
			Events int    `json:"events"`
			Error  string `json:"error"`
		} `json:"tracee"`
		Falco struct {
			Alerts int    `json:"alerts"`
			Error  string `json:"error"`
		} `json:"falco"`
		Missing []string `json:"missing"`
	} `json:"coverage"`
}

type risk struct {
	Score float64 `json:"risk_score"`
	Level string  `json:"risk_level"`
}

type client struct {
	baseURL string
	http    *http.Client
}

func TestSandboxAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test skipped in short mode")
	}
	requireCommand(t, "podman")
	requireCommand(t, "ssh")
	if _, err := os.Stat("/dev/kvm"); err != nil {
		t.Skip("/dev/kvm is not available")
	}

	root := repositoryRoot(t)
	key := filepath.Join(root, "storage", "penguinbox", "ssh", "id_ed25519")
	knownHosts := filepath.Join(root, "storage", "penguinbox", "known_hosts")

	if os.Getenv("PENGUINBOX_E2E_SKIP_BUILD") != "1" {
		run(t, root, "./build-image.sh", "localhost/penguinbox:latest")
	}

	started := ensureBox(t, root)
	t.Cleanup(func() {
		if started && os.Getenv("PENGUINBOX_E2E_KEEP") != "1" {
			_ = exec.Command("podman", "rm", "-f", containerName).Run()
		}
	})

	sshOptions := []string{
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile=" + knownHosts,
		"-o", "ConnectTimeout=20",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "ForwardAgent=no",
		"-o", "PasswordAuthentication=no",
		"-i", key,
		"-p", hostSSHPort,
	}
	sshArgs := append(append([]string{}, sshOptions...), "penguinbox@127.0.0.1")
	waitSSH(t, sshArgs)
	waitForProvision(t, sshArgs)

	api := &client{
		baseURL: "http://127.0.0.1:" + hostAPIPort,
		http:    &http.Client{Timeout: 5 * time.Minute},
	}
	waitAPI(t, api)

	var health health
	api.get(t, "/health", &health)
	if len(health.Scanners.Rows) < 4 {
		t.Fatalf("health scanners = %#v", health.Scanners.Rows)
	}
	for _, want := range []string{"elf", "yara", "tracee", "falco"} {
		found := false
		for _, row := range health.Scanners.Rows {
			if row.Name == want && row.Exists {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("health has no %s scanner: %#v", want, health.Scanners.Rows)
		}
	}
	if len(health.Rules.Static.Files) == 0 {
		t.Fatal("health has no custom YARA rules")
	}
	if len(health.Rules.Behavioral.Files) == 0 {
		t.Fatal("health has no custom behavioral rules")
	}

	var profiles struct {
		Profiles []string `json:"profiles"`
	}
	api.get(t, "/api/edr/profiles", &profiles)
	if len(profiles.Profiles) != 0 {
		t.Fatalf("EDR profiles = %#v", profiles.Profiles)
	}

	sample := filepath.Join(t.TempDir(), "sample.sh")
	if err := os.WriteFile(sample, []byte("#!/bin/sh\ncat /proc/self/maps >/dev/null\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	uploaded := api.upload(t, sample)
	if len(uploaded.FileInfo.MD5) != 32 || uploaded.FileInfo.Size == 0 {
		t.Fatalf("upload = %+v", uploaded.FileInfo)
	}
	if uploaded.FileInfo.OriginalName != "sample.sh" {
		t.Fatalf("upload name = %q", uploaded.FileInfo.OriginalName)
	}

	var static analyzeResponse
	api.post(t, "/analyze/static/"+uploaded.FileInfo.MD5+"?wait=1", &static)
	if static.Status != "success" {
		t.Fatalf("static status = %q: %s", static.Status, static.Error)
	}
	if _, ok := static.Results["elf"]; !ok {
		t.Fatal("static results have no elf block")
	}
	var yara staticYARA
	if err := json.Unmarshal(static.Results["yara"], &yara); err != nil {
		t.Fatalf("decode yara: %v", err)
	}
	if !hasYARARule(yara, "PenguinBox_ProcMaps") {
		t.Fatalf("custom YARA rule did not match: %+v", yara)
	}

	var dynamicRequest analyzeResponse
	api.post(t, "/analyze/dynamic/"+uploaded.FileInfo.MD5+"?wait=1", &dynamicRequest)
	if dynamicRequest.Status != "success" {
		t.Fatalf("dynamic status = %q: %s", dynamicRequest.Status, dynamicRequest.Error)
	}
	var dynamic dynamicResult
	api.get(t, "/api/results/dynamic/"+uploaded.FileInfo.MD5, &dynamic)
	if dynamic.Run.ExitCode != 0 || dynamic.Run.TimedOut {
		t.Fatalf("dynamic run = %+v", dynamic.Run)
	}
	if dynamic.Coverage.Tracee.Events == 0 {
		t.Fatalf("Tracee captured no events: %+v", dynamic.Coverage)
	}
	if dynamic.Coverage.Falco.Alerts == 0 {
		t.Fatalf("Falco produced no alerts: %+v", dynamic.Coverage)
	}
	if !hasCollector(dynamic.Findings.Events, "tracee") {
		t.Fatal("dynamic events have no tracee collector")
	}
	if !hasFalcoRule(dynamic.Findings.Events, "PenguinBox EDR - Process Memory Map Read") {
		t.Fatal("custom behavioral rule did not fire")
	}

	var assessment risk
	api.get(t, "/api/results/risk/"+uploaded.FileInfo.MD5, &assessment)
	if assessment.Level == "" || assessment.Score < 0 {
		t.Fatalf("risk = %+v", assessment)
	}

	guestListeners := run(t, root, "ssh", append(sshArgs, "ss", "-ltn")...)
	if !strings.Contains(guestListeners, "0.0.0.0:1338") && !strings.Contains(guestListeners, "*:1338") {
		t.Fatalf("API is not listening on the guest network:\n%s", guestListeners)
	}
	if strings.Contains(guestListeners, "127.0.0.1:1338") {
		t.Fatalf("API is still loopback-only; passt cannot reach it:\n%s", guestListeners)
	}
	hostListeners := run(t, root, "ss", "-ltn")
	if !strings.Contains(hostListeners, "127.0.0.1:1338") {
		t.Fatalf("API is not published on the host loopback:\n%s", hostListeners)
	}
	if strings.Contains(hostListeners, "0.0.0.0:1338") || strings.Contains(hostListeners, "*:1338") {
		t.Fatalf("API is published beyond host loopback:\n%s", hostListeners)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func requireCommand(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s is not installed", name)
	}
}

func ensureBox(t *testing.T, root string) bool {
	t.Helper()
	exists := exec.Command("podman", "container", "exists", containerName).Run() == nil
	if exists && os.Getenv("PENGUINBOX_E2E_RESET") == "1" {
		_ = exec.Command("podman", "rm", "-f", containerName).Run()
		_ = os.Remove(filepath.Join(root, "storage", "penguinbox", "known_hosts"))
		exists = false
	}
	if !exists {
		if err := os.MkdirAll(filepath.Join(root, "storage"), 0o755); err != nil {
			t.Fatal(err)
		}
		run(t, root, "podman", "run", "-d", "--name", containerName,
			"--device", "/dev/kvm",
			"-p", "127.0.0.1:2223:2222",
			"-p", "127.0.0.1:8007:8006",
			"-p", "127.0.0.1:1338:1338",
			"-v", filepath.Join(root, "storage")+":/storage:z",
			"-e", "VM_NAME=penguinbox",
			"-e", "RESET="+os.Getenv("PENGUINBOX_E2E_RESET"),
			"-e", "HOST_SSH_PORT=2223",
			"-e", "HOST_WEB_PORT=8007",
			"localhost/penguinbox:latest")
		return true
	}
	running := strings.TrimSpace(run(t, root, "podman", "ps", "--filter", "name=^"+containerName+"$", "--format", "{{.Names}}"))
	if running != containerName {
		run(t, root, "podman", "start", containerName)
		return true
	}
	return false
}

func waitSSH(t *testing.T, sshArgs []string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(repositoryRoot(t), "storage", "penguinbox", "ssh", "id_ed25519")); err == nil {
			cmd := exec.Command("ssh", append(sshArgs, "true")...)
			cmd.Stdout = io.Discard
			cmd.Stderr = io.Discard
			if cmd.Run() == nil {
				return
			}
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatal("guest SSH did not become ready")
}

func waitForProvision(t *testing.T, sshArgs []string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Minute)
	var lastOutput []byte
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		cmd := exec.CommandContext(ctx, "ssh", append(sshArgs,
			"cloud-init status --wait >/dev/null && systemctl is-active penguinboxd.service >/dev/null")...)
		output, err := cmd.CombinedOutput()
		cancel()
		if err == nil {
			return
		}
		lastOutput, lastErr = output, err
		time.Sleep(5 * time.Second)
	}
	diag, _ := exec.Command("ssh", append(sshArgs,
		"cloud-init status --long; systemctl status penguinboxd.service --no-pager -l; tail -80 /var/log/penguinbox/provision.log")...).CombinedOutput()
	t.Fatalf("provisioning failed: %v\n%s\n%s", lastErr, lastOutput, diag)
}

func waitAPI(t *testing.T, api *client) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if err := api.getErr("/health", nil); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatal("sandbox API did not answer on the published port")
}

func run(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}

func (c *client) get(t *testing.T, path string, out any) {
	t.Helper()
	if err := c.getErr(path, out); err != nil {
		t.Fatal(err)
	}
}

func (c *client) getErr(path string, out any) error {
	response, err := c.http.Get(c.baseURL + path)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s: %s", path, response.Status, body)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

func (c *client) post(t *testing.T, path string, out any) {
	t.Helper()
	response, err := c.http.Post(c.baseURL+path, "application/json", nil)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<20))
	if err != nil {
		t.Fatalf("POST %s: read: %v", path, err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("POST %s: %s: %s", path, response.Status, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("POST %s: decode: %v\n%s", path, err, body)
	}
}

func (c *client) upload(t *testing.T, path string) uploadResponse {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(part, file); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, c.baseURL+"/upload", &body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := c.http.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("upload: %s: %s", response.Status, data)
	}
	var uploaded uploadResponse
	if err := json.Unmarshal(data, &uploaded); err != nil {
		t.Fatalf("upload decode: %v\n%s", err, data)
	}
	return uploaded
}

func hasYARARule(report staticYARA, name string) bool {
	for _, match := range report.Matches {
		if match.Rule == name {
			return true
		}
	}
	return false
}

func hasCollector(events []json.RawMessage, collector string) bool {
	for _, raw := range events {
		var event map[string]any
		if json.Unmarshal(raw, &event) == nil && event["collector"] == collector {
			return true
		}
	}
	return false
}

func hasFalcoRule(events []json.RawMessage, rule string) bool {
	for _, raw := range events {
		var event map[string]any
		if json.Unmarshal(raw, &event) != nil || event["collector"] != "falco" {
			continue
		}
		if event["rule"] == rule {
			return true
		}
	}
	return false
}
