package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Scanner        ScannerConfig        `mapstructure:"scanner"`
	Docker         DockerConfig         `mapstructure:"docker"`
	SecurityChecks SecurityChecksConfig `mapstructure:"security_checks"`
	Reporting      ReportingConfig      `mapstructure:"reporting"`
	Logging        LoggingConfig        `mapstructure:"logging"`
	Metrics        MetricsConfig        `mapstructure:"metrics"`
}

// MetricsConfig contains metrics settings
type MetricsConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Port    string `mapstructure:"port"`
	Path    string `mapstructure:"path"`
}

// ScannerConfig contains scanner-specific settings
type ScannerConfig struct {
	MaxConcurrentScans int      `mapstructure:"max_concurrent_scans"`
	Timeout            string   `mapstructure:"timeout"`
	ScanStopped        bool     `mapstructure:"scan_stopped_containers"`
	ExcludeImages      []string `mapstructure:"exclude_images"`
	ExcludeNames       []string `mapstructure:"exclude_names"`
}

// DockerConfig contains Docker-specific settings
type DockerConfig struct {
	SocketPath string `mapstructure:"socket_path"`
	APIVersion string `mapstructure:"api_version"`
	TLSVerify  bool   `mapstructure:"tls_verify"`
}

// SecurityChecksConfig contains security check configurations
type SecurityChecksConfig struct {
	RootUserCheck          bool `mapstructure:"root_user_check"`
	ExposedPortsCheck      bool `mapstructure:"exposed_ports_check"`
	VulnerabilityCheck     bool `mapstructure:"vulnerability_check"`
	SecretsCheck           bool `mapstructure:"secrets_check"`
	NetworkPolicyCheck     bool `mapstructure:"network_policy_check"`
	ResourceLimitsCheck    bool `mapstructure:"resource_limits_check"`
	ImageIntegrityCheck    bool `mapstructure:"image_integrity_check"`
	ProcessMonitoringCheck bool `mapstructure:"process_monitoring_check"`
}

// ReportingConfig contains reporting settings
type ReportingConfig struct {
	OutputDir      string   `mapstructure:"output_dir"`
	Formats        []string `mapstructure:"formats"`
	IncludeDetails bool     `mapstructure:"include_details"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	EnableFile bool   `mapstructure:"enable_file"`
	FilePath   string `mapstructure:"file_path"`
}

// LoadConfig loads configuration from file and environment
func LoadConfig() (*Config, error) {
	v := viper.New()

	setDefaults(v)

	v.SetConfigName("config")
	v.SetConfigType("yaml")

	configPaths := []string{
		".",
		"./configs",
		"/etc/docker-security-scanner",
		os.Getenv("HOME") + "/.docker-security-scanner",
	}

	for _, path := range configPaths {
		v.AddConfigPath(path)
	}

	v.AutomaticEnv()
	v.SetEnvPrefix("DSS")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to decode config: %w", err)
	}

	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	v.SetDefault("scanner.max_concurrent_scans", 10)
	v.SetDefault("scanner.timeout", "30m")
	v.SetDefault("scanner.scan_stopped_containers", false)

	v.SetDefault("docker.socket_path", "/var/run/docker.sock")
	v.SetDefault("docker.api_version", "1.41")
	v.SetDefault("docker.tls_verify", false)

	v.SetDefault("security_checks.root_user_check", true)
	v.SetDefault("security_checks.exposed_ports_check", true)
	v.SetDefault("security_checks.vulnerability_check", true)
	v.SetDefault("security_checks.secrets_check", true)
	v.SetDefault("security_checks.network_policy_check", true)
	v.SetDefault("security_checks.resource_limits_check", true)
	v.SetDefault("security_checks.image_integrity_check", true)
	v.SetDefault("security_checks.process_monitoring_check", true)

	v.SetDefault("reporting.output_dir", "./reports")
	v.SetDefault("reporting.formats", []string{"json"})
	v.SetDefault("reporting.include_details", true)

	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "text")
	v.SetDefault("logging.output", "stdout")
	v.SetDefault("logging.enable_file", false)
	v.SetDefault("logging.file_path", "/var/log/docker-security-scanner.log")

	v.SetDefault("metrics.enabled", true)
	v.SetDefault("metrics.port", ":9090")
	v.SetDefault("metrics.path", "/metrics")
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	if config.Docker.SocketPath == "" {
		return fmt.Errorf("docker socket path is required")
	}

	if config.Scanner.MaxConcurrentScans <= 0 {
		return fmt.Errorf("max concurrent scans must be greater than 0")
	}

	if config.Reporting.OutputDir != "" {
		if err := os.MkdirAll(config.Reporting.OutputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	if config.Logging.EnableFile && config.Logging.FilePath != "" {
		logDir := filepath.Dir(config.Logging.FilePath)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}
	}

	if config.Metrics.Enabled && config.Metrics.Port == "" {
		return fmt.Errorf("metrics port is required when metrics are enabled")
	}

	return nil
}

// GetConfigFilePath returns the path to the configuration file
func GetConfigFilePath() string {
	configPaths := []string{
		"./config.yaml",
		"./configs/config.yaml",
		"/etc/docker-security-scanner/config.yaml",
		os.Getenv("HOME") + "/.docker-security-scanner/config.yaml",
	}

	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}
