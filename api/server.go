package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"securitydos/engine"
	"securitydos/logger"
	"securitydos/metrics"
	"securitydos/reports"
	"securitydos/safety"
	"securitydos/scenario"

	"github.com/gorilla/websocket"
)

// Server is the REST + WebSocket control API
type Server struct {
	guard     *safety.Guard
	collector *metrics.Collector
	log       *logger.Logger

	mu        sync.Mutex
	eng       *engine.Engine
	testCancel context.CancelFunc
	testID    string
	operator  string
	activeScenario *scenario.Scenario

	srv       *http.Server

	upgrader websocket.Upgrader

	analysisConfig AnalysisConfig
	dashboardFS    fs.FS
	configsFS      fs.FS

	lastProbeSuccess bool
	lastProbeMsg     string
}

type AnalysisConfig struct {
	BreakingPointRate    float64
	LatencyThresholdMs   float64
	SecurityTriggerRate  float64
}

// StartRequest is the payload for POST /api/start
type StartRequest struct {
	ScenarioYAML string `json:"scenario_yaml"`
	Operator     string `json:"operator"`
}

// StatusResponse is returned by GET /api/status
type StatusResponse struct {
	Running       bool      `json:"running"`
	TestID        string    `json:"test_id,omitempty"`
	Operator      string    `json:"operator,omitempty"`
	Target        string    `json:"target,omitempty"`
	TestType      string    `json:"test_type,omitempty"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	KillSwitch    bool      `json:"kill_switch_active"`
	ActiveWorkers int64     `json:"active_workers"`
}

// NewServer creates the API server
func NewServer(guard *safety.Guard, col *metrics.Collector, log *logger.Logger, ana AnalysisConfig, dashboard fs.FS, configs fs.FS) *Server {
	s := &Server{
		guard:          guard,
		collector:      col,
		log:            log,
		analysisConfig: ana,
		dashboardFS:    dashboard,
		configsFS:      configs,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
	return s
}

// Handler returns the HTTP mux with all routes registered
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// REST endpoints
	mux.Handle("/api/status", s.auth(http.HandlerFunc(s.handleStatus)))
	mux.Handle("/api/metrics", s.auth(http.HandlerFunc(s.handleMetrics)))
	mux.Handle("/api/start", s.auth(http.HandlerFunc(s.handleStart)))
	mux.Handle("/api/stop", s.auth(http.HandlerFunc(s.handleStop)))
	mux.Handle("/api/config", s.auth(http.HandlerFunc(s.handleConfig)))
	mux.Handle("/api/config/profiles", s.auth(http.HandlerFunc(s.handleGetProfiles)))
	mux.Handle("/api/history", s.auth(http.HandlerFunc(s.handleHistory)))
	mux.Handle("/api/reports", s.auth(http.HandlerFunc(s.handleReportsList)))
	mux.Handle("/api/kill", s.auth(http.HandlerFunc(s.handleKill)))
	mux.Handle("/api/report", s.auth(http.HandlerFunc(s.handleReport)))
	mux.Handle("/api/exit", s.auth(http.HandlerFunc(s.handleExit)))

	// WebSocket stream
	mux.Handle("/ws/metrics", s.auth(http.HandlerFunc(s.handleWS)))

	// Dashboard static files (Embedded)
	mux.Handle("/logs/", s.auth(http.StripPrefix("/logs/", http.FileServer(http.Dir("logs")))))
	mux.Handle("/", http.FileServer(http.FS(s.dashboardFS)))

	return corsMiddleware(mux)
}

// auth middleware checks Authorization header or token query param (for WebSockets)
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "" {
			token = strings.TrimPrefix(token, "Bearer ")
		} else {
			token = r.URL.Query().Get("token")
		}
		
		if err := s.guard.Authorize(token); err != nil {
			jsonError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Handlers ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	resp := StatusResponse{
		Running:    s.guard.IsRunning(),
		KillSwitch: s.guard.IsKillSwitchActive(),
	}
	if s.eng != nil {
		resp.ActiveWorkers = s.eng.ActiveWorkers()
		resp.TestID = s.testID
		resp.Operator = s.operator
	}
	if s.activeScenario != nil {
		resp.Target = s.activeScenario.Target
		resp.TestType = string(s.activeScenario.TestType)
	}
	s.mu.Unlock()
	jsonOK(w, resp)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Return a combined config view
	jsonOK(w, map[string]interface{}{
		"safety":   s.guard.CurrentConfig(),
		"analysis": s.analysisConfig,
	})
}

func (s *Server) handleGetProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Scan disk
	diskFiles, _ := filepath.Glob("configs/scenario_*.yaml")
	
	// 2. Scan embedded
	embedFiles, _ := fs.Glob(s.configsFS, "scenario_*.yaml")

	profiles := []scenario.Scenario{}
	seenURLs := make(map[string]bool)

	// Helper to process files
	processFile := func(path string, isEmbedded bool) {
		var data []byte
		var err error
		if isEmbedded {
			data, err = fs.ReadFile(s.configsFS, path)
		} else {
			data, err = os.ReadFile(path)
		}
		
		if err != nil {
			return
		}
		
		sc, err := scenario.Parse(data)
		if err != nil {
			return
		}
		
		// Avoid duplicates if same file exists on disk and embedded
		if !seenURLs[sc.Target+string(sc.TestType)] {
			profiles = append(profiles, *sc)
			seenURLs[sc.Target+string(sc.TestType)] = true
		}
	}

	for _, f := range diskFiles {
		processFile(f, false)
	}
	for _, f := range embedFiles {
		processFile(f, true)
	}

	s.log.Info(fmt.Sprintf("Served %d test profiles to dashboard", len(profiles)))
	jsonOK(w, profiles)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonOK(w, s.collector.Current())
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonOK(w, s.collector.History())
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req StartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if s.guard.IsRunning() {
		jsonError(w, "a test is already running", http.StatusConflict)
		return
	}
	if s.guard.IsKillSwitchActive() {
		jsonError(w, "kill switch is active; call /api/kill to reset", http.StatusForbidden)
		return
	}

	// Parse scenario
	sc, err := scenario.Parse([]byte(req.ScenarioYAML))
	if err != nil {
		jsonError(w, "scenario parse error: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Apply default analysis thresholds from global config if not overridden in scenario
	if sc.LatencyThresholdMs <= 0 {
		sc.LatencyThresholdMs = s.analysisConfig.LatencyThresholdMs
	}
	if sc.BreakingPointRate <= 0 {
		sc.BreakingPointRate = s.analysisConfig.BreakingPointRate
	}
	if sc.SecurityTriggerRate <= 0 {
		sc.SecurityTriggerRate = s.analysisConfig.SecurityTriggerRate
	}

	// Safety validations
	if err := s.guard.ValidateTarget(sc.Target); err != nil {
		s.log.Warn("Blocked: target not allowed", logger.WithTarget(sc.Target))
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := s.guard.ValidateRPS(sc.MaxRPS()); err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}
	if err := s.guard.ValidateDuration(sc.TotalDuration()); err != nil {
		jsonError(w, err.Error(), http.StatusForbidden)
		return
	}

	// Generate test ID: domain-YYYYMMDD-HHMMSS
	testID := s.generateTestID(sc.Target)
	operator := req.Operator
	if operator == "" {
		operator = "unknown"
	}

	// Parse request timeout from scenario
	reqTimeout, _ := time.ParseDuration(sc.Timeout)
	if reqTimeout <= 0 {
		reqTimeout = 30 * time.Second
	}

	// Create engine
	cfg := engine.EngineConfig{
		Target:     sc.Target,
		Method:     sc.Method,
		Headers:    sc.Headers,
		Timeout:    reqTimeout, // Use parsed timeout
		HTTP2:      sc.HTTP2,
		KeepAlive:  sc.KeepAlive,
		MaxWorkers: sc.MaxWorkers,
		InitialRPS: sc.Stages[0].RPS,
		Unit:       sc.Unit,
		UserAgentPrefix: sc.UserAgentPrefix,
		Evasion:    sc.Evasion,
		FollowRedirect: sc.FollowRedirect,
		TestID:     testID,
	}

	s.collector.Reset()
	eng, err := engine.New(cfg, s.collector, s.guard)
	if err != nil {
		jsonError(w, "engine init error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	s.mu.Lock()
	s.eng = eng
	s.testCancel = cancel
	s.testID = testID
	s.operator = operator
	s.activeScenario = sc
	s.mu.Unlock()

	s.guard.MarkTestStart()

	s.log.Audit(operator, sc.Target, string(sc.TestType), 0, 0, 0)
	s.log.Info(fmt.Sprintf("Test started: %s", testID),
		logger.WithTarget(sc.Target),
		logger.WithOperator(operator),
	)

		// Run engine asynchronously
		go func() {
			defer s.guard.MarkTestStop()
			defer cancel()
			if err := eng.Run(ctx, sc.Stages); err != nil {
				s.log.Error("Engine stopped: " + err.Error())
			}
			s.log.Info(fmt.Sprintf("Test completed: %s", testID))

			// Per request user: Perform post-test health check probe
			s.log.Info("Running post-test recovery health probe...")
			probeSuccess, probeMsg := eng.VerifyTargetHealth()

			s.mu.Lock()
			s.lastProbeSuccess = probeSuccess
			s.lastProbeMsg = probeMsg
			s.mu.Unlock()

			if probeSuccess {
				s.log.Info(fmt.Sprintf("Recovery Pulse: Target is UP (%s)", probeMsg))
			} else {
				s.log.Warn(fmt.Sprintf("Recovery Pulse: Target is DOWN/ERROR (%s)", probeMsg))
			}

			// Auto-generate reports
			s.collector.Flush()
			history := s.collector.History()
			rep := reports.Build(testID, operator, sc, history, probeSuccess, probeMsg)
			_ = rep.SaveJSON(fmt.Sprintf("logs/report_%s.json", testID))
			_ = rep.SaveMarkdown(fmt.Sprintf("logs/report_%s.md", testID))
			s.log.Info(fmt.Sprintf("Reports saved to logs/report_%s.{json,md}", testID))
		}()

	jsonOK(w, map[string]string{
		"status":  "started",
		"test_id": testID,
		"target":  sc.Target,
	})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	cancel := s.testCancel
	eng := s.eng
	s.mu.Unlock()

	if !s.guard.IsRunning() || eng == nil {
		jsonError(w, "no test is running", http.StatusBadRequest)
		return
	}
	eng.Stop()
	if cancel != nil {
		cancel()
	}
	s.guard.MarkTestStop()
	s.log.Info("Test stopped via API")
	jsonOK(w, map[string]string{"status": "stopped"})
}

func (s *Server) handleKill(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.guard.ActivateKillSwitch()
		if s.eng != nil {
			s.eng.Stop()
		}
		if s.testCancel != nil {
			s.testCancel()
		}
		s.guard.MarkTestStop()
		s.log.Warn("KILL SWITCH ACTIVATED via API")
		jsonOK(w, map[string]string{"status": "kill switch activated"})
	case http.MethodDelete:
		s.guard.ResetKillSwitch()
		s.log.Info("Kill switch reset via API")
		jsonOK(w, map[string]string{"status": "kill switch reset"})
	default:
		jsonError(w, "use POST to activate, DELETE to reset", http.StatusMethodNotAllowed)
	}
}

// handleConfig already defined at line 155

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	testID := s.testID
	operator := s.operator
	sc := s.activeScenario
	s.mu.Unlock()

	if sc == nil {
		jsonError(w, "no test has been run yet", http.StatusNotFound)
		return
	}
	s.collector.Flush()
	history := s.collector.History()
	s.mu.Lock()
	pSuccess := s.lastProbeSuccess
	pMsg := s.lastProbeMsg
	s.mu.Unlock()

	rep := reports.Build(testID, operator, sc, history, pSuccess, pMsg)
	jsonOK(w, rep)
}

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WS upgrade error:", err)
		return
	}
	defer conn.Close()

	ch := s.collector.Subscribe()
	defer s.collector.Unsubscribe(ch)

	// Send current snapshot immediately on connect
	snap := s.collector.Current()
	if data, err := json.Marshal(snap); err == nil {
		conn.WriteMessage(websocket.TextMessage, data)
	}

	for snap := range ch {
		data, err := json.Marshal(snap)
		if err != nil {
			continue
		}
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			break
		}
	}
}

// Run starts the HTTP server
func (s *Server) Run(addr string) error {
	s.srv = &http.Server{
		Addr:         addr,
		Handler:      s.Handler(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	s.log.Info(fmt.Sprintf("API server listening on %s", addr))
	return s.srv.ListenAndServe()
}

// Stop gracefully shuts down the server and any running tests
func (s *Server) Stop() {
	s.log.Info("Shutting down API server...")
	s.mu.Lock()
	if s.eng != nil {
		s.eng.Stop()
	}
	if s.testCancel != nil {
		s.testCancel()
	}
	s.mu.Unlock()

	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.srv.Shutdown(ctx)
	}
}

// --- helpers ---

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) handleExit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.log.Info("Remote shutdown requested via dashboard")
	jsonOK(w, map[string]string{"status": "shutting_down"})

	// Give a small delay to allow response to reach the client
	go func() {
		time.Sleep(1 * time.Second)
		s.mu.Lock()
		if s.eng != nil {
			s.eng.Stop()
		}
		s.mu.Unlock()
		if s.srv != nil {
			s.srv.Shutdown(context.Background())
		}
	}()
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) generateTestID(target string) string {
	domain := "target"
	if u, err := url.Parse(target); err == nil {
		h := u.Hostname()
		if h != "" {
			domain = h
			// Include first path segment if it exists to help distinguish
			p := strings.Trim(u.Path, "/")
			if p != "" {
				segments := strings.Split(p, "/")
				if segments[0] != "" {
					domain = fmt.Sprintf("%s_%s", domain, segments[0])
				}
			}
		}
	}
	// Clean domain name for filename
	domain = strings.ReplaceAll(domain, ".", "_")
	ts := time.Now().Format("20060102_150405")
	baseID := fmt.Sprintf("%s_%s", domain, ts)

	// Ensure uniqueness
	id := baseID
	for i := 1; ; i++ {
		if _, err := os.Stat(fmt.Sprintf("logs/report_%s.json", id)); os.IsNotExist(err) {
			break
		}
		id = fmt.Sprintf("%s_%d", baseID, i)
	}
	return id
}

type ReportInfo struct {
	TestID      string    `json:"test_id"`
	Target      string    `json:"target"`
	TestType    string    `json:"test_type"`
	SuccessRate float64   `json:"success_rate"`
	GeneratedAt time.Time `json:"generated_at"`
	Size        int64     `json:"size"`
}

func (s *Server) handleReportsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	files, err := filepath.Glob("logs/report_*.json")
	if err != nil {
		jsonError(w, "failed to list reports: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var reportsList []ReportInfo
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}

		// Use anonymous struct for fast partial decode
		var meta struct {
			Meta struct {
				TestID      string    `json:"test_id"`
				GeneratedAt time.Time `json:"generated_at"`
			} `json:"meta"`
			Config struct {
				Target   string `json:"target"`
				TestType string `json:"test_type"`
			} `json:"config"`
			Summary struct {
				SuccessRate float64 `json:"overall_success_rate"`
			} `json:"summary"`
		}

		if err := json.Unmarshal(data, &meta); err == nil {
			info, _ := os.Stat(f)
			reportsList = append(reportsList, ReportInfo{
				TestID:      meta.Meta.TestID,
				Target:      meta.Config.Target,
				TestType:    meta.Config.TestType,
				SuccessRate: meta.Summary.SuccessRate,
				GeneratedAt: meta.Meta.GeneratedAt,
				Size:        info.Size(),
			})
		}
	}

	// Sort by date descending
	sort.Slice(reportsList, func(i, j int) bool {
		return reportsList[i].GeneratedAt.After(reportsList[j].GeneratedAt)
	})

	jsonOK(w, reportsList)
}
