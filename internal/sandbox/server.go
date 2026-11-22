package sandbox

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Config holds the runtime parameters for the PenguinBox sandbox API server.
type Config struct {
	Listen          string
	StateDir        string
	FalcoLog        string
	Image           string
	PayloadNetwork  string
	APIToken        string
	Podman          string
	HostAliasFile   string
	Tracee          string
	TraceeHelper    string
	TraceeEvents    string
	YARA            string
	YARARules       string
	FalcoRules      string
	DetonateTimeout time.Duration
	MaxUpload       int64
	MaxEvents       int
}

// Server serves the LitterBox-compatible sandbox HTTP API.
type Server struct {
	cfg     Config
	store   *store
	runGate chan struct{}
	trace   *traceCollector
	mux     *http.ServeMux
}

// New initializes storage, starts the long-lived Tracee collector, and wires
// HTTP routes for the sandbox API.
func New(cfg Config) (*Server, error) {
	state, err := newStore(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:     cfg,
		store:   state,
		runGate: make(chan struct{}, 1),
		trace:   newTraceCollector(cfg),
		mux:     http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

// Close releases background collector resources.
func (s *Server) Close() {
	if s.trace != nil {
		s.trace.close()
	}
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("GET /api/edr/profiles", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"profiles": []string{}})
	})
	s.mux.HandleFunc("GET /api/rules", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.rules())
	})
	s.mux.HandleFunc("POST /upload", s.handleUpload)
	s.mux.HandleFunc("POST /analyze/static/{md5}", func(w http.ResponseWriter, r *http.Request) {
		s.handleAnalyze(w, r, "static")
	})
	s.mux.HandleFunc("POST /analyze/dynamic/{md5}", func(w http.ResponseWriter, r *http.Request) {
		s.handleAnalyze(w, r, "dynamic")
	})
	s.mux.HandleFunc("/analyze/edr/{rest...}", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusNotImplemented, map[string]any{"status": "error", "error": "EDR profiles are not configured"})
	})
	s.mux.HandleFunc("GET /api/results/{kind}/{md5}", s.handleResult)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := validateLoopbackHost(r.Host); err != nil {
		http.Error(w, "forbidden host", http.StatusForbidden)
		return
	}
	if s.cfg.APIToken != "" && r.URL.Path != "/health" && !authorizedRequest(r, s.cfg.APIToken) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.mux.ServeHTTP(w, r)
}

type scanner struct {
	Group   string `json:"group"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Enabled bool   `json:"enabled"`
	Exists  bool   `json:"exists"`
}

type rulesStatus struct {
	Static struct {
		Dir   string   `json:"dir"`
		Files []string `json:"files"`
	} `json:"static"`
	Behavioral struct {
		Dir    string   `json:"dir"`
		Files  []string `json:"files"`
		Engine string   `json:"engine"`
	} `json:"behavioral"`
}

type healthResult struct {
	Scanners struct {
		Rows []scanner `json:"rows"`
	} `json:"scanners"`
	EDRAgents struct {
		Agents []any `json:"agents"`
	} `json:"edr_agents"`
	Issues []string    `json:"issues"`
	Rules  rulesStatus `json:"rules"`
}

type fileInfo struct {
	MD5          string       `json:"md5"`
	SHA256       string       `json:"sha256"`
	Size         int64        `json:"size"`
	OriginalName string       `json:"original_name"`
	DetectedType detectedType `json:"detected_type"`
}

type uploadResponse struct {
	FileInfo fileInfo `json:"file_info"`
}

type infoResult struct {
	FileInfo fileInfo      `json:"file_info"`
	Static   *staticReport `json:"static,omitempty"`
}

type riskResult struct {
	Score   float64  `json:"risk_score"`
	Level   string   `json:"risk_level"`
	Factors []string `json:"risk_factors,omitempty"`
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	health := healthResult{Issues: []string{}}
	health.EDRAgents.Agents = []any{}
	for _, name := range []string{"elf", "yara"} {
		exists := true
		if name == "yara" {
			_, err := os.Stat(s.cfg.YARA)
			exists = err == nil
		}
		health.Scanners.Rows = append(health.Scanners.Rows, scanner{
			Group: "static", Name: name, Status: "ok", Enabled: true, Exists: exists,
		})
	}
	for _, name := range []string{"tracee", "falco"} {
		exists := true
		switch name {
		case "tracee":
			_, err := os.Stat(s.cfg.Tracee)
			exists = err == nil
		case "falco":
			_, err := os.Stat(s.cfg.FalcoLog)
			exists = err == nil
			if !exists {
				_, err = exec.LookPath("falco")
				exists = err == nil
			}
		}
		health.Scanners.Rows = append(health.Scanners.Rows, scanner{
			Group: "dynamic", Name: name, Status: "ok", Enabled: true, Exists: exists,
		})
		if !exists {
			health.Issues = append(health.Issues, fmt.Sprintf("%s is not available", name))
		}
	}
	if _, err := exec.LookPath(s.cfg.Podman); err != nil {
		health.Issues = append(health.Issues, "podman is not available")
	}
	if _, err := os.Stat(s.cfg.TraceeHelper); err != nil {
		health.Issues = append(health.Issues, "tracee helper is not available")
	}
	health.Rules = s.rules()
	if len(health.Rules.Static.Files) == 0 {
		health.Issues = append(health.Issues, "no custom YARA rules configured")
	}
	if len(health.Rules.Behavioral.Files) == 0 {
		health.Issues = append(health.Issues, "no custom behavioral rules configured")
	}
	writeJSON(w, http.StatusOK, health)
}

func (s *Server) rules() rulesStatus {
	var status rulesStatus
	status.Static.Dir = s.cfg.YARARules
	if files, err := listFiles(s.cfg.YARARules, ".yar", ".yara"); err == nil {
		status.Static.Files = files
	} else {
		status.Static.Files = []string{}
	}
	status.Behavioral.Dir = s.cfg.FalcoRules
	status.Behavioral.Engine = "falco"
	if files, err := listFiles(s.cfg.FalcoRules, ".yaml", ".yml"); err == nil {
		status.Behavioral.Files = files
	} else {
		status.Behavioral.Files = []string{}
	}
	return status
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUpload+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "invalid multipart upload", http.StatusBadRequest)
		return
	}
	defer r.MultipartForm.RemoveAll()
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file field", http.StatusBadRequest)
		return
	}
	defer file.Close()
	info, err := s.store.saveUpload(file, header.Filename, s.cfg.MaxUpload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fi := fileInfoFromUpload(info)
	if err := s.store.saveJSON(info.MD5, "info", infoResult{FileInfo: fi}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, uploadResponse{FileInfo: fi})
}

func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request, kind string) {
	md5 := r.PathValue("md5")
	if !md5Pattern.MatchString(md5) {
		http.NotFound(w, r)
		return
	}
	info, err := s.store.loadUpload(md5)
	if err != nil {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	switch kind {
	case "static":
		report := analyzeArtifact(r.Context(), info.Path, s.cfg.YARA, s.cfg.YARARules)
		if err := s.store.saveJSON(md5, "static", report); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "error": err.Error()})
			return
		}
		s.store.removeResult(md5, "risk")
		writeJSON(w, http.StatusOK, map[string]any{"status": "success", "results": report})
	case "dynamic":
		result, err := s.runDynamic(r.Context(), info)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"status": "error", "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "success", "results": result})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	md5 := r.PathValue("md5")
	if !md5Pattern.MatchString(md5) {
		http.NotFound(w, r)
		return
	}
	switch kind {
	case "edr":
		writeJSON(w, http.StatusOK, map[string]any{"profiles": []string{}})
	case "holygrail":
		http.NotFound(w, r)
	case "risk":
		if !s.store.hasResult(md5, "risk") {
			if err := s.buildRisk(md5); err != nil {
				http.NotFound(w, r)
				return
			}
		}
		s.serveResult(w, md5, "risk")
	case "info":
		var info infoResult
		if err := s.store.loadJSON(md5, "info", &info); err != nil {
			http.NotFound(w, r)
			return
		}
		var static staticReport
		if s.store.loadJSON(md5, "static", &static) == nil {
			info.Static = &static
		}
		writeJSON(w, http.StatusOK, info)
	case "static", "dynamic":
		s.serveResult(w, md5, kind)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) serveResult(w http.ResponseWriter, md5, kind string) {
	data, err := os.ReadFile(s.store.resultPath(md5, kind))
	if err != nil {
		http.Error(w, "result not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) buildRisk(md5 string) error {
	var static staticReport
	staticErr := s.store.loadJSON(md5, "static", &static)
	var dynamic dynamicResult
	dynamicErr := s.store.loadJSON(md5, "dynamic", &dynamic)
	if staticErr != nil && dynamicErr != nil {
		return fmt.Errorf("no static or dynamic result")
	}
	return s.store.saveJSON(md5, "risk", computeRisk(static, dynamic))
}

func computeRisk(static staticReport, dynamic dynamicResult) riskResult {
	risk := riskResult{Factors: []string{}}
	add := func(weight float64, factor string) {
		risk.Score += weight
		risk.Factors = append(risk.Factors, factor)
	}
	for _, item := range static.ELF.Findings {
		switch item.Severity {
		case "critical":
			add(4, "static: "+item.Rule)
		case "high":
			add(3, "static: "+item.Rule)
		case "medium":
			add(1.5, "static: "+item.Rule)
		}
	}
	if matches, ok := static.YARA["matches"].([]any); ok {
		for range matches {
			add(3, "yara: custom rule matched")
		}
	}
	for _, raw := range dynamic.Findings.Events {
		var event map[string]any
		if json.Unmarshal(raw, &event) != nil || event["collector"] != "falco" {
			continue
		}
		priority, _ := event["priority"].(string)
		switch strings.ToLower(priority) {
		case "emergency":
			add(5, "falco: emergency")
		case "alert":
			add(4, "falco: alert")
		case "critical":
			add(4, "falco: critical")
		case "error":
			add(3, "falco: error")
		case "warning":
			add(2, "falco: warning")
		case "notice":
			add(1, "falco: notice")
		case "informational", "info":
			add(0.5, "falco: informational")
		}
	}
	risk.Score = min(risk.Score, 10)
	switch {
	case risk.Score >= 9:
		risk.Level = "critical"
	case risk.Score >= 7:
		risk.Level = "high"
	case risk.Score >= 4:
		risk.Level = "medium"
	case risk.Score > 0:
		risk.Level = "low"
	default:
		risk.Level = "none"
	}
	if len(risk.Factors) > 16 {
		risk.Factors = risk.Factors[:16]
	}
	return risk
}

func fileInfoFromUpload(info upload) fileInfo {
	return fileInfo{
		MD5: info.MD5, SHA256: info.SHA256, Size: info.Size,
		OriginalName: info.Name, DetectedType: info.DetectedType,
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// ValidateLoopback rejects any bind address that is not a literal loopback IP.
func ValidateLoopback(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("must bind a loopback IP, got %q", address)
	}
	return nil
}

// validateLoopbackHost blocks DNS-rebinding requests from non-loopback Host
// headers when the API is reached through the published loopback port.
func validateLoopbackHost(hostHeader string) error {
	if hostHeader == "" {
		return nil
	}
	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("non-loopback host %q", hostHeader)
}

func authorizedRequest(r *http.Request, token string) bool {
	provided, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}
