package sandbox

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var md5Pattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type detectedType struct {
	Family string `json:"family,omitempty"`
	Type   string `json:"type,omitempty"`
}

type upload struct {
	MD5          string       `json:"md5"`
	SHA256       string       `json:"sha256"`
	Name         string       `json:"name"`
	Path         string       `json:"path,omitempty"`
	Size         int64        `json:"size"`
	DetectedType detectedType `json:"detected_type,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
}

type store struct {
	root string
}

func newStore(root string) (*store, error) {
	for _, dir := range []string{root, filepath.Join(root, "uploads"), filepath.Join(root, "runs"), filepath.Join(root, "tmp")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}
	return &store{root: root}, nil
}

func (s *store) uploadDir(md5 string) string {
	return filepath.Join(s.root, "uploads", md5)
}

func (s *store) resultPath(md5, kind string) string {
	return filepath.Join(s.uploadDir(md5), kind+".json")
}

func (s *store) removeResult(md5, kind string) {
	if md5Pattern.MatchString(md5) {
		_ = os.Remove(s.resultPath(md5, kind))
	}
}

// saveUpload streams one artifact to the store and returns its metadata. An
// existing artifact with the same MD5 and SHA-256 is reused; the first name is kept.
func (s *store) saveUpload(r io.Reader, name string, limit int64) (upload, error) {
	name = safeName(name)
	tmp, err := os.CreateTemp(filepath.Join(s.root, "tmp"), "upload-*")
	if err != nil {
		return upload{}, fmt.Errorf("create upload: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	md5Hash := md5.New()
	sha256Hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, md5Hash, sha256Hash), io.LimitReader(r, limit+1))
	if err != nil {
		tmp.Close()
		return upload{}, fmt.Errorf("write upload: %w", err)
	}
	if written > limit {
		tmp.Close()
		return upload{}, fmt.Errorf("artifact exceeds %d bytes", limit)
	}
	if written == 0 {
		tmp.Close()
		return upload{}, errors.New("artifact is empty")
	}
	if err := tmp.Close(); err != nil {
		return upload{}, fmt.Errorf("close upload: %w", err)
	}

	md5Value := hex.EncodeToString(md5Hash.Sum(nil))
	sha256Value := hex.EncodeToString(sha256Hash.Sum(nil))
	dir := s.uploadDir(md5Value)
	payloadPath := filepath.Join(dir, "payload")

	if existing, err := s.loadUpload(md5Value); err == nil {
		if existing.SHA256 != "" && existing.SHA256 != sha256Value {
			return upload{}, fmt.Errorf("md5 collision detected for %s", md5Value)
		}
		return existing, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return upload{}, fmt.Errorf("create upload directory: %w", err)
	}
	if err := os.Rename(tmpName, payloadPath); err != nil {
		return upload{}, fmt.Errorf("commit upload: %w", err)
	}
	if err := os.Chmod(payloadPath, 0o700); err != nil {
		return upload{}, fmt.Errorf("chmod upload: %w", err)
	}

	info := upload{
		MD5:          md5Value,
		SHA256:       sha256Value,
		Name:         name,
		Path:         payloadPath,
		Size:         written,
		DetectedType: detectType(payloadPath),
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.saveJSON(md5Value, "upload", info); err != nil {
		return upload{}, err
	}
	return info, nil
}

func (s *store) loadUpload(md5 string) (upload, error) {
	if !md5Pattern.MatchString(md5) {
		return upload{}, fmt.Errorf("invalid md5 %q", md5)
	}
	var info upload
	if err := s.loadJSON(md5, "upload", &info); err != nil {
		return upload{}, err
	}
	if info.Path == "" {
		return upload{}, fmt.Errorf("stored upload path is invalid")
	}
	relative, err := filepath.Rel(s.uploadDir(md5), info.Path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return upload{}, fmt.Errorf("stored upload path is invalid")
	}
	if _, err := os.Stat(info.Path); err != nil {
		return upload{}, fmt.Errorf("stored artifact: %w", err)
	}
	return info, nil
}

func (s *store) saveJSON(md5, kind string, value any) error {
	if !md5Pattern.MatchString(md5) {
		return fmt.Errorf("invalid md5 %q", md5)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", kind, err)
	}
	path := s.resultPath(md5, kind)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create result directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+kind+"-*")
	if err != nil {
		return fmt.Errorf("create %s result: %w", kind, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod %s result: %w", kind, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s result: %w", kind, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %s result: %w", kind, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s result: %w", kind, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("commit %s result: %w", kind, err)
	}
	return nil
}

func (s *store) loadJSON(md5, kind string, value any) error {
	if !md5Pattern.MatchString(md5) {
		return fmt.Errorf("invalid md5 %q", md5)
	}
	data, err := os.ReadFile(s.resultPath(md5, kind))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("decode %s result: %w", kind, err)
	}
	return nil
}

func (s *store) hasResult(md5, kind string) bool {
	_, err := os.Stat(s.resultPath(md5, kind))
	return err == nil
}

func safeName(name string) string {
	clean := filepath.Base(strings.TrimSpace(sanitizeText(name)))
	if clean == "" || clean == "." || clean == string(filepath.Separator) {
		return "payload"
	}
	return clean
}

func detectType(path string) detectedType {
	file, err := os.Open(path)
	if err != nil {
		return detectedType{Family: "unknown"}
	}
	defer file.Close()
	head := make([]byte, 4)
	n, _ := io.ReadFull(file, head)
	head = head[:n]
	switch {
	case len(head) >= 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F':
		return detectedType{Family: "ELF", Type: "executable"}
	case len(head) >= 2 && head[0] == 'M' && head[1] == 'Z':
		return detectedType{Family: "PE", Type: "executable"}
	case len(head) >= 2 && head[0] == '#' && head[1] == '!':
		return detectedType{Family: "script", Type: "text"}
	default:
		return detectedType{Family: "unknown", Type: "binary"}
	}
}
