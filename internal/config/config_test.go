package config

import (
	"os"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Create a temporary directory for config test
	tmpDir, err := os.MkdirTemp("", "config-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Change working directory to temp dir so we don't pick up local config
	originalWd, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to chdir: %v", err)
	}
	defer os.Chdir(originalWd)

	// Clear environment variables that might interfere
	os.Unsetenv("DSS_DOCKER_SOCKET_PATH")
	os.Unsetenv("DSS_METRICS_ENABLED")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config with defaults: %v", err)
	}

	if cfg.Scanner.MaxConcurrentScans != 10 {
		t.Errorf("Expected default MaxConcurrentScans=10, got %d", cfg.Scanner.MaxConcurrentScans)
	}

	if cfg.Docker.SocketPath != "/var/run/docker.sock" {
		t.Errorf("Expected default SocketPath=/var/run/docker.sock, got %s", cfg.Docker.SocketPath)
	}

	if !cfg.Metrics.Enabled {
		t.Error("Expected metrics to be enabled by default")
	}

	if cfg.Metrics.Port != ":9090" {
		t.Errorf("Expected default Metrics Port=:9090, got %s", cfg.Metrics.Port)
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		shouldErr bool
	}{
		{
			name: "Valid Config",
			config: &Config{
				Scanner: ScannerConfig{MaxConcurrentScans: 5},
				Docker:  DockerConfig{SocketPath: "/tmp/docker.sock"},
				Metrics: MetricsConfig{Enabled: true, Port: ":9090"},
			},
			shouldErr: false,
		},
		{
			name: "Missing Socket Path",
			config: &Config{
				Scanner: ScannerConfig{MaxConcurrentScans: 5},
				Docker:  DockerConfig{SocketPath: ""},
			},
			shouldErr: true,
		},
		{
			name: "Invalid Concurrency",
			config: &Config{
				Scanner: ScannerConfig{MaxConcurrentScans: 0},
				Docker:  DockerConfig{SocketPath: "/tmp/docker.sock"},
			},
			shouldErr: true,
		},
		{
			name: "Missing Metrics Port when Enabled",
			config: &Config{
				Scanner: ScannerConfig{MaxConcurrentScans: 5},
				Docker:  DockerConfig{SocketPath: "/tmp/docker.sock"},
				Metrics: MetricsConfig{Enabled: true, Port: ""},
			},
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			if (err != nil) != tt.shouldErr {
				t.Errorf("validateConfig() error = %v, shouldErr %v", err, tt.shouldErr)
			}
		})
	}
}
