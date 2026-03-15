package reports

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"securitydos/metrics"
	"securitydos/scenario"
)

// Report holds full test run results for export
type Report struct {
	Meta     ReportMeta         `json:"meta"`
	Config   ReportConfig       `json:"config"`
	Summary  ReportSummary      `json:"summary"`
	Timeline []metrics.Snapshot `json:"timeline"`
	Analysis ReportAnalysis     `json:"analysis"`
}

// ReportMeta identifies the test run
type ReportMeta struct {
	TestID      string    `json:"test_id"`
	Operator    string    `json:"operator"`
	GeneratedAt time.Time `json:"generated_at"`
	ToolVersion string    `json:"tool_version"`
}

// ReportConfig captures test parameters
type ReportConfig struct {
	Target          string            `json:"target"`
	TestType        string            `json:"test_type"`
	Method          string            `json:"method"`
	HTTP2           bool              `json:"http2"`
	KeepAlive       bool              `json:"keep_alive"`
	MaxWorkers      int               `json:"max_workers"`
	UserAgentPrefix string            `json:"user_agent_prefix"`
	Headers         map[string]string `json:"headers"`
	Stages          []scenario.Stage  `json:"stages"`
	TotalDuration   time.Duration     `json:"total_duration"`
	PeakRPS         int               `json:"peak_rps"`
	Unit            string            `json:"unit"`
}

// ReportSummary provides aggregated statistics
type ReportSummary struct {
	TotalRequests  int64   `json:"total_requests"`
	SuccessCount   int64   `json:"success_count"`
	ErrorCount     int64   `json:"error_count"`
	TimeoutCount   int64   `json:"timeout_count"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
	P95LatencyMs   float64 `json:"p95_latency_ms"`
	P99LatencyMs   float64 `json:"p99_latency_ms"`
	MaxLatencyMs   float64 `json:"max_latency_ms"`
	AvgRPS         float64 `json:"avg_rps"`
	PeakRPS        float64 `json:"peak_rps"`
	AvgTPS         float64 `json:"avg_tps"`
	PeakTPS        float64          `json:"peak_tps"`
	OverallSuccess float64          `json:"overall_success_rate"`
	OverallError   float64          `json:"overall_error_rate"`
	StatusCodes    map[string]int64 `json:"status_codes"`
}

// ReportAnalysis holds security-relevant findings
type ReportAnalysis struct {
	BreakingPointRPS      float64  `json:"breaking_point_rps"`
	LatencyDegradationAt  float64  `json:"latency_degradation_rps"`
	ErrorSpikeAt          float64  `json:"error_spike_rps"`
	RateLimitTriggeredAt  float64  `json:"rate_limit_rps"`
	RecoveryObserved      bool     `json:"recovery_observed"`
	LoadBalancerImbalance bool     `json:"load_balancer_imbalance"`
	FinalHealthCheckPassed bool     `json:"final_health_check_passed"`
	FinalHealthCheckMsg    string   `json:"final_health_check_msg"`
	Observations          []string `json:"observations"`
}

// Build constructs a report from history and scenario
func Build(testID, operator string, sc *scenario.Scenario, history []metrics.Snapshot, probeSuccess bool, probeMsg string) *Report {
	// Deep copy history to prevent modification by collector if still running
	historyCopy := make([]metrics.Snapshot, len(history))
	copy(historyCopy, history)

	r := &Report{
		Meta: ReportMeta{
			TestID:      testID,
			Operator:    operator,
			GeneratedAt: time.Now().UTC(),
			ToolVersion: "Red Team v1.0",
		},
		Config: ReportConfig{
			Target:          sc.Target,
			TestType:        string(sc.TestType),
			Method:          sc.Method,
			HTTP2:           sc.HTTP2,
			KeepAlive:       sc.KeepAlive,
			MaxWorkers:      sc.MaxWorkers,
			UserAgentPrefix: sc.UserAgentPrefix,
			Headers:         sc.Headers,
			Stages:          sc.Stages,
			TotalDuration:   sc.TotalDuration(),
			PeakRPS:         sc.MaxRPS(),
			Unit:            sc.Unit,
		},
		Timeline: historyCopy,
	}

	r.Summary = computeSummary(historyCopy)
	r.Analysis = analyze(historyCopy, r.Summary, sc.LatencyThresholdMs, sc.BreakingPointRate, sc.SecurityTriggerRate, probeSuccess, probeMsg)
	return r
}

func computeSummary(history []metrics.Snapshot) ReportSummary {
	if len(history) == 0 {
		return ReportSummary{}
	}
	var sumRPS, sumTPS, sumLatency, sumP95, sumP99 float64
	var peakRPS, peakTPS, maxLat float64
	var activeWindows float64
	scCumulative := make(map[string]int64)

	last := history[len(history)-1]
	totalSuccess := last.SuccessCount
	totalErr := last.ErrorCount
	totalTimeout := last.TimeoutCount

	for _, s := range history {
		sumRPS += s.RPS
		sumTPS += s.TPS

		if s.RPS > peakRPS {
			peakRPS = s.RPS
		}
		if s.TPS > peakTPS {
			peakTPS = s.TPS
		}
		if s.MaxLatencyMs > maxLat {
			maxLat = s.MaxLatencyMs
		}

		// Aggregate all status codes (including TIMEOUT)
		for code, count := range s.StatusCodes {
			scCumulative[code] += count
		}

		// Only count active windows (RPS > 0) towards averages to avoid idle distortion
		if s.RPS > 0 {
			sumLatency += s.AvgLatencyMs
			sumP95 += s.P95LatencyMs
			sumP99 += s.P99LatencyMs
			activeWindows++
		}
	}

	avgDiv := activeWindows
	if avgDiv == 0 {
		avgDiv = 1 // Prevent div by zero, but logically r.Timeline existed
	}

	// Calculate total consistent with the codes we summed
	var totalReq int64
	for _, count := range scCumulative {
		totalReq += count
	}

	n := float64(len(history))
	successRate := float64(0)
	if totalReq > 0 {
		successRate = float64(totalSuccess) / float64(totalReq)
	}

	return ReportSummary{
		TotalRequests:  totalReq,
		SuccessCount:   totalSuccess,
		ErrorCount:     totalErr,
		TimeoutCount:   totalTimeout,
		AvgLatencyMs:   sumLatency / avgDiv,
		P95LatencyMs:   sumP95 / avgDiv,
		P99LatencyMs:   sumP99 / avgDiv,
		MaxLatencyMs:   maxLat,
		AvgRPS:         sumRPS / n,
		PeakRPS:        peakRPS,
		AvgTPS:         sumTPS / n,
		PeakTPS:        peakTPS,
		OverallSuccess: successRate,
		OverallError:   1 - successRate,
		StatusCodes:    scCumulative,
	}
}

func analyze(history []metrics.Snapshot, sum ReportSummary, latencyDegThreshold, breakingPointThreshold, securityTriggerRate float64, probeSuccess bool, probeMsg string) ReportAnalysis {
	a := ReportAnalysis{
		Observations:           []string{},
		FinalHealthCheckPassed: probeSuccess,
		FinalHealthCheckMsg:    probeMsg,
	}

	const minSampleForRL = 50 // Minimum requests in window for rate-limit detection

	var prevLatency float64
	var foundBreaking, foundLatDeg, foundRL bool
	var consecutiveErrors int
	var postPeakErrors int
	var peakRPS float64

	for _, s := range history {
		if s.RPS > peakRPS {
			peakRPS = s.RPS
		}

		// Improved Breaking Point Detection: Needs 3 consecutive seconds of > threshold error
		if !foundBreaking && s.RPS > 10 {
			if s.ErrorRate > breakingPointThreshold {
				consecutiveErrors++
				if consecutiveErrors >= 3 {
					a.BreakingPointRPS = s.RPS
					foundBreaking = true
					a.Observations = append(a.Observations, fmt.Sprintf("Confirmed Breaking Point: Error rate consistently exceeded %.0f%% at %.0f RPS", breakingPointThreshold*100, s.RPS))
				}
			} else {
				consecutiveErrors = 0
			}
		}

		// Latency degradation
		if !foundLatDeg && prevLatency > 0 && s.AvgLatencyMs > latencyDegThreshold && s.RPS > 10 {
			a.LatencyDegradationAt = s.RPS
			foundLatDeg = true
			a.Observations = append(a.Observations, fmt.Sprintf("Latency Degradation: Average response time exceeded %.1fs at %.0f RPS", latencyDegThreshold/1000, s.RPS))
		}

		// Rate limit detection
		if !foundRL && s.RPS >= minSampleForRL {
			var total4xx int64
			var dominantCode string
			var maxCount int64

			for code, count := range s.StatusCodes {
				if strings.HasPrefix(code, "4") {
					total4xx += count
					if count > maxCount {
						maxCount = count
						dominantCode = code
					}
				}
			}

			// If more than securityTriggerRate of traffic is 4xx, it's likely a security trigger
			if float64(total4xx)/s.RPS > securityTriggerRate {
				a.RateLimitTriggeredAt = s.RPS
				foundRL = true

				label := "Security Interception detected"
				if dominantCode == "429" {
					label = "Rate Limit (429) active"
				} else if dominantCode == "403" {
					label = "WAF/Access Block (403) active"
				}

				a.Observations = append(a.Observations, fmt.Sprintf("%s at %.0f RPS", label, s.RPS))
			}
		}

		// Improved Recovery detection logic
		// If we previously had high errors and now they are low while load is still present
		if (foundBreaking || foundRL) && s.ErrorRate < 0.02 && s.RPS > 5 {
			postPeakErrors++
		} else if s.ErrorRate > breakingPointThreshold {
			// If errors come back, reset recovery counter
			postPeakErrors = 0
		}

		// Load Balancer Imbalance detection
		// If Max latency is > 10x Avg latency and sample size is decent, 
		// it suggests some requests are hitting slow/unhealthy nodes while others are fast.
		if !a.LoadBalancerImbalance && s.RPS > 20 && s.MaxLatencyMs > s.AvgLatencyMs*10 && s.AvgLatencyMs > 0 {
			a.LoadBalancerImbalance = true
			a.Observations = append(a.Observations, fmt.Sprintf("Potential Load Balancer Imbalance: Significant latency variance detected (Max: %.0fms vs Avg: %.0fms)", s.MaxLatencyMs, s.AvgLatencyMs))
		}

		prevLatency = s.AvgLatencyMs
	}

	if postPeakErrors >= 3 || ( (foundBreaking || foundRL) && probeSuccess ) {
		a.RecoveryObserved = true
		msg := "System Recovery: Performance stabilized and error rate dropped after initial instability"
		if !foundBreaking && !foundRL && probeSuccess {
			// If we never broke but probe is OK, it's just stable
			a.RecoveryObserved = true // Technically true
		} else if probeSuccess {
			msg = fmt.Sprintf("System Recovery Confirmed: Server is responsive (%s) after high-load phase", probeMsg)
		}
		a.Observations = append(a.Observations, msg)
	}

	if !foundBreaking && !foundRL && !foundLatDeg {
		a.Observations = append(a.Observations, "System Stability: No critical performance degradation detected during test")
	}

	if sum.OverallError > 0.2 {
		// Find most frequent error
		maxCount := int64(-1)
		domError := "unknown"
		for code, count := range sum.StatusCodes {
			if !strings.HasPrefix(code, "2") && count > maxCount {
				maxCount = count
				domError = code
			}
		}

		a.Observations = append(a.Observations, fmt.Sprintf("High overall error rate: %.1f%% (Mainly code %s)", sum.OverallError*100, domError))
	}

	if sum.P99LatencyMs > 5000 {
		a.Observations = append(a.Observations, fmt.Sprintf("p99 latency critically high: %.0fms", sum.P99LatencyMs))
	}

	if len(a.Observations) == 0 {
		a.Observations = append(a.Observations, "No critical anomalies detected during test window")
	}

	return a
}

// SaveJSON writes the report as a JSON file
func (r *Report) SaveJSON(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// SaveMarkdown writes the report as a Markdown file
func (r *Report) SaveMarkdown(path string) error {
	var sb strings.Builder

	sb.WriteString("# Security DoS – Test Report\n\n")
	sb.WriteString(fmt.Sprintf("**Test ID:** `%s`  \n", r.Meta.TestID))
	sb.WriteString(fmt.Sprintf("**Operator:** %s  \n", r.Meta.Operator))
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", r.Meta.GeneratedAt.Format(time.RFC1123)))
	sb.WriteString(fmt.Sprintf("**Tool:** %s  \n\n", r.Meta.ToolVersion))

	sb.WriteString("## Test Configuration\n\n")
	sb.WriteString("| Parameter | Value |\n|---|---|\n")
	sb.WriteString(fmt.Sprintf("| Target | `%s` |\n", r.Config.Target))
	sb.WriteString(fmt.Sprintf("| Test Type | `%s` |\n", r.Config.TestType))
	sb.WriteString(fmt.Sprintf("| Method | `%s` |\n", r.Config.Method))
	sb.WriteString(fmt.Sprintf("| HTTP/2 | `%v` |\n", r.Config.HTTP2))
	sb.WriteString(fmt.Sprintf("| Keep-Alive | `%v` |\n", r.Config.KeepAlive))
	sb.WriteString(fmt.Sprintf("| Max Workers | `%d` |\n", r.Config.MaxWorkers))
	uaDisplay := "Default (Random Pool)"
	if r.Config.UserAgentPrefix != "" {
		uaDisplay = fmt.Sprintf("Custom: %s", r.Config.UserAgentPrefix)
	}
	sb.WriteString(fmt.Sprintf("| User-Agent | `%s` |\n", uaDisplay))
	if len(r.Config.Headers) > 0 {
		hStr := ""
		for k, v := range r.Config.Headers {
			hStr += fmt.Sprintf("%s: %s<br/>", k, v)
		}
		sb.WriteString(fmt.Sprintf("| Custom Headers | %s |\n", hStr))
	}
	sb.WriteString(fmt.Sprintf("| Target Load | `%d %s` |\n", r.Config.PeakRPS, r.Config.Unit))
	sb.WriteString(fmt.Sprintf("| Total Duration | `%v` |\n\n", r.Config.TotalDuration))

	sb.WriteString("### Stage Timeline\n\n")
	sb.WriteString("| Stage | RPS | Duration |\n|---|---|---|\n")
	for _, s := range r.Config.Stages {
		sb.WriteString(fmt.Sprintf("| %s | %d | %v |\n", s.Name, s.RPS, s.Duration))
	}
	sb.WriteString("\n")

	sb.WriteString("## Results Summary\n\n")
	sb.WriteString("| Metric | Value |\n|---|---|\n")
	sb.WriteString(fmt.Sprintf("| Total Requests | `%d` |\n", r.Summary.TotalRequests))
	sb.WriteString(fmt.Sprintf("| Success | `%d` (%.1f%%) |\n", r.Summary.SuccessCount, r.Summary.OverallSuccess*100))
	sb.WriteString(fmt.Sprintf("| Errors | `%d` (%.1f%%) |\n", r.Summary.ErrorCount, r.Summary.OverallError*100))
	sb.WriteString(fmt.Sprintf("| Timeouts | `%d` |\n", r.Summary.TimeoutCount))
	sb.WriteString(fmt.Sprintf("| Avg RPS | `%.1f` |\n", r.Summary.AvgRPS))
	sb.WriteString(fmt.Sprintf("| Max RPS | `%.1f` |\n", r.Summary.PeakRPS))
	sb.WriteString(fmt.Sprintf("| Avg TPS | `%.1f` |\n", r.Summary.AvgTPS))
	sb.WriteString(fmt.Sprintf("| Max TPS | `%.1f` |\n", r.Summary.PeakTPS))
	sb.WriteString(fmt.Sprintf("| Avg Latency | `%.2f ms` |\n", r.Summary.AvgLatencyMs))
	sb.WriteString(fmt.Sprintf("| p95 Latency | `%.2f ms` |\n", r.Summary.P95LatencyMs))
	sb.WriteString(fmt.Sprintf("| p99 Latency | `%.2f ms` |\n", r.Summary.P99LatencyMs))
	sb.WriteString(fmt.Sprintf("| Max Latency | `%.2f ms` |\n\n", r.Summary.MaxLatencyMs))

	sb.WriteString("## Security Analysis\n\n")
	if r.Analysis.BreakingPointRPS > 0 {
		sb.WriteString(fmt.Sprintf("- **Breaking Point:** %.0f RPS\n", r.Analysis.BreakingPointRPS))
	}
	if r.Analysis.LatencyDegradationAt > 0 {
		sb.WriteString(fmt.Sprintf("- **Latency Degradation Onset:** %.0f RPS\n", r.Analysis.LatencyDegradationAt))
	}
	if r.Analysis.RateLimitTriggeredAt > 0 {
		sb.WriteString(fmt.Sprintf("- **Rate Limit Triggered At:** %.0f RPS\n", r.Analysis.RateLimitTriggeredAt))
	}

	recoveryStatus := "No"
	if r.Analysis.RecoveryObserved {
		recoveryStatus = "Yes"
	} else if r.Analysis.FinalHealthCheckPassed && r.Analysis.BreakingPointRPS == 0 {
		recoveryStatus = "N/A (Stable)"
	}

	sb.WriteString(fmt.Sprintf("- **Recovery Observed:** %s\n", recoveryStatus))
	sb.WriteString(fmt.Sprintf("- **Post-Test Health Probe:** %s\n\n", r.Analysis.FinalHealthCheckMsg))

	sb.WriteString("### Observations\n\n")
	for _, obs := range r.Analysis.Observations {
		sb.WriteString(fmt.Sprintf("- %s\n", obs))
	}

	sb.WriteString("\n---\n*Generated by Security DoS – Authorized Security Testing Only*\n")

	return os.WriteFile(path, []byte(sb.String()), 0644)
}
