package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveUploadRoundTrip(t *testing.T) {
	store, err := newStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("MZ\x90\x00payload")
	info, err := store.saveUpload(bytes.NewReader(content), "../../payload.exe", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "payload.exe" {
		t.Fatalf("name = %q, want payload.exe", info.Name)
	}
	if info.MD5 == "" || info.SHA256 == "" || info.Size != int64(len(content)) {
		t.Fatalf("upload metadata = %+v", info)
	}
	loaded, err := store.loadUpload(info.MD5)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Path != info.Path || loaded.Name != info.Name {
		t.Fatalf("loaded = %+v, want %+v", loaded, info)
	}
	if data, err := os.ReadFile(loaded.Path); err != nil || !bytes.Equal(data, content) {
		t.Fatalf("stored payload = %q, err=%v", data, err)
	}
}

func TestSaveUploadReusesContent(t *testing.T) {
	store, err := newStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.saveUpload(strings.NewReader("same"), "first.bin", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.saveUpload(strings.NewReader("same"), "second.bin", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if first.MD5 != second.MD5 || first.Name != second.Name {
		t.Fatalf("duplicate upload = %+v, %+v", first, second)
	}
}

func TestSaveUploadLimit(t *testing.T) {
	store, err := newStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.saveUpload(strings.NewReader("too large"), "x", 2); err == nil {
		t.Fatal("expected upload limit error")
	}
}

func TestLoadUploadRejectsInvalidID(t *testing.T) {
	store, err := newStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.loadUpload("../escape"); err == nil {
		t.Fatal("expected invalid md5 error")
	}
}

func TestSafeName(t *testing.T) {
	tests := map[string]string{
		"../../etc/passwd":    "passwd",
		"":                    "payload",
		"\x00":                "payload",
		"a/b/c.bin":           "c.bin",
		"\x1b[31mfoo\nbar.sh": "[31mfoobar.sh",
	}
	for input, want := range tests {
		if got := safeName(input); got != want {
			t.Errorf("safeName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestSaveUploadRejectsMD5Collision(t *testing.T) {
	store, err := newStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.saveUpload(strings.NewReader("same"), "first.bin", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	first.SHA256 = strings.Repeat("0", 64)
	if err := store.saveJSON(first.MD5, "upload", first); err != nil {
		t.Fatal(err)
	}
	if _, err := store.saveUpload(strings.NewReader("same"), "collision.bin", 1<<20); err == nil {
		t.Fatal("expected MD5 collision error")
	}
}

func TestSaveJSONRejectsTraversal(t *testing.T) {
	store, err := newStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.saveJSON("../escape", "static", map[string]any{}); err == nil {
		t.Fatal("expected invalid md5 error")
	}
	if _, err := os.Stat(filepath.Join(store.root, "..", "escape")); !os.IsNotExist(err) {
		t.Fatalf("unexpected file: %v", err)
	}
}
