package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"securitydos/api"
	"securitydos/logger"
	"securitydos/metrics"
	"securitydos/safety"

	"gopkg.in/yaml.v3"
)

//go:embed all:dashboard/*
var dashboardEmbed embed.FS

//go:embed all:configs/*
var configsEmbed embed.FS

// AppConfig is parsed from config.yaml
type AppConfig struct {
	Server struct {
		Addr string `yaml:"addr"`
	} `yaml:"server"`
	Safety  safety.Config `yaml:"safety"`
	Logging struct {
		Path string `yaml:"path"`
	} `yaml:"logging"`
	Analysis AnalysisConfig `yaml:"analysis"`
}

type AnalysisConfig struct {
	BreakingPointRate   float64 `yaml:"breaking_point_rate"`
	LatencyThresholdMs  float64 `yaml:"latency_threshold_ms"`
	SecurityTriggerRate float64 `yaml:"security_trigger_rate"`
}

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to config.yaml")
	enableGuard := flag.Bool("guard", false, "activate safety guard (enforces config limits)")
	flag.Parse()

	// Load config
	cfg, err := loadConfig(*configPath, configsEmbed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: cannot load config: %v\n", err)
		os.Exit(1)
	}

	addr := cfg.Server.Addr
	if addr == "" {
		addr = ":8090"
	}

	// Ensure logs directory exists
	os.MkdirAll("logs", 0755)

	logPath := cfg.Logging.Path
	if logPath == "" {
		logPath = fmt.Sprintf("logs/security_dos_%s.jsonl", time.Now().Format("20060102_150405"))
	}

	// Initialise logger
	log, err := logger.New(logPath, "SYSTEM")
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: logger init: %v\n", err)
		os.Exit(1)
	}

	log.Info("SecurityDoS v1.0 starting up")
	log.Info(fmt.Sprintf("Config loaded from: %s", *configPath))

	// Safety guard (Opt-in)
	guard := safety.New(cfg.Safety, *enableGuard)
	if *enableGuard {
		log.Warn("Safety Guard: ACTIVE (Enforcing policies from config.yaml)")
	} else {
		log.Warn("Safety Guard: INACTIVE (Unrestricted mode - use with caution)")
	}

	// Metrics collector (keep 3600 snapshots = 1 hour)
	collector := metrics.NewCollector(3600)
	defer collector.Stop()

	// API server
	dashboardFS, _ := fs.Sub(dashboardEmbed, "dashboard")
	configsFS, _ := fs.Sub(configsEmbed, "configs")
	srv := api.NewServer(guard, collector, log, api.AnalysisConfig{
		BreakingPointRate:   cfg.Analysis.BreakingPointRate,
		LatencyThresholdMs:  cfg.Analysis.LatencyThresholdMs,
		SecurityTriggerRate: cfg.Analysis.SecurityTriggerRate,
	}, dashboardFS, configsFS)

	log.Info(fmt.Sprintf("Dashboard available at http://localhost%s", addr))
	if *enableGuard {
		log.Info(fmt.Sprintf("Allowed targets: %v", cfg.Safety.AllowedTargets))
	} else {
		log.Info("Allowed targets: ALL (Guard bypassed)")
	}

	// Graceful shutdown channel
	stopSignals := make(chan os.Signal, 1)
	signal.Notify(stopSignals, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := srv.Run(addr); err != nil && err != http.ErrServerClosed {
			log.Error("Server exited with error: " + err.Error())
			os.Exit(1)
		}
	}()

	// Wait for signal
	sig := <-stopSignals
	log.Info(fmt.Sprintf("Received signal %v, shutting down...", sig))

	// Shutdown logic
	srv.Stop() // Added Stop method to server if it doesn't exist, or just use Shutdown

	log.Info("System shut down gracefully")
}

func loadConfig(path string, embedded embed.FS) (*AppConfig, error) {
	var data []byte
	var err error

	// 1. Try reading from disk
	data, err = os.ReadFile(path)
	if err != nil {
		// 2. Fallback to embedded if disk fails
		data, err = embedded.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config not found on disk or embedded: %w", err)
		}
	}
	cfg := &AppConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
