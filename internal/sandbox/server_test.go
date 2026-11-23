package sandbox

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	rules := filepath.Join(dir, "yara")
	if err := os.MkdirAll(rules, 0o700); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{
		StateDir:     filepath.Join(dir, "state"),
		FalcoLog:     filepath.Join(dir, "falco.json"),
		Image:        "localhost/penguinbox-payload:latest",
		Podman:       "podman",
		Tracee:       "/nonexistent/tracee",
		TraceeHelper: "/nonexistent/helper",
		YARA:         "/nonexistent/yara",
		YARARules:    rules,
		FalcoRules:   filepath.Join(dir, "falco"),
		MaxUpload:    1 << 20,
		MaxEvents:    100,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func uploadTestFile(t *testing.T, srv *Server, name, content string) fileInfo {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:1338/upload", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("upload status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var response uploadResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.FileInfo.MD5 == "" {
		t.Fatal("upload response has no md5")
	}
	return response.FileInfo
}

func TestUploadAndStatic(t *testing.T) {
	srv := testServer(t)
	info := uploadTestFile(t, srv, "sample.sh", "#!/bin/sh\ncat /proc/self/maps\n")
	if info.OriginalName != "sample.sh" || info.Size == 0 {
		t.Fatalf("file info = %+v", info)
	}

	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:1338/analyze/static/"+info.MD5, nil)
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("analyze status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Status  string          `json:"status"`
		Results json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "success" {
		t.Fatalf("status = %q, body = %s", response.Status, recorder.Body.String())
	}
	var report map[string]json.RawMessage
	if err := json.Unmarshal(response.Results, &report); err != nil {
		t.Fatal(err)
	}
	if _, ok := report["elf"]; !ok {
		t.Fatal("static result has no elf block")
	}
	if _, ok := report["yara"]; !ok {
		t.Fatal("static result has no yara block")
	}

	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1338/api/results/static/"+info.MD5, nil)
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("static result status = %d", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1338/api/results/info/"+info.MD5, nil)
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("info status = %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"static"`) {
		t.Fatalf("info has no static block: %s", recorder.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1338/api/results/risk/"+info.MD5, nil)
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("risk status = %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestHealthAndRules(t *testing.T) {
	srv := testServer(t)
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1338/health", nil)
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("health status = %d", recorder.Code)
	}
	var health healthResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if len(health.Scanners.Rows) != 4 {
		t.Fatalf("scanners = %#v", health.Scanners.Rows)
	}
	if health.Rules.Static.Dir == "" || health.Rules.Behavioral.Dir == "" {
		t.Fatalf("rules = %+v", health.Rules)
	}

	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1338/api/edr/profiles", nil)
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || strings.TrimSpace(recorder.Body.String()) != "{\"profiles\":[]}" {
		t.Fatalf("profiles = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestUploadMissingFile(t *testing.T) {
	srv := testServer(t)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:1338/upload", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestResultNotFoundAndInvalidID(t *testing.T) {
	srv := testServer(t)
	for _, target := range []string{
		"http://127.0.0.1:1338/api/results/static/0123456789abcdef0123456789abcdef",
		"http://127.0.0.1:1338/api/results/static/invalid",
		"http://127.0.0.1:1338/analyze/static/invalid",
	} {
		method := http.MethodGet
		if strings.Contains(target, "/analyze/") {
			method = http.MethodPost
		}
		request := httptest.NewRequest(method, target, nil)
		recorder := httptest.NewRecorder()
		srv.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s %s status = %d, want 404", method, target, recorder.Code)
		}
	}
}

func TestBearerTokenAuth(t *testing.T) {
	srv := testServer(t)
	srv.cfg.APIToken = "secret-token"

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1338/health", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/health status = %d, want 200", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1338/api/rules", nil)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/api/rules without token status = %d, want 401", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1338/api/rules", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/api/rules with wrong token status = %d, want 401", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1338/api/rules", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/rules with valid token status = %d, want 200", rec.Code)
	}
}
