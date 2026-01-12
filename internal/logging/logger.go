package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Logger represents the application logger
type Logger struct {
	*logrus.Logger
	config *Config
}

// Config contains logging configuration
type Config struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Output     string `mapstructure:"output"`
	EnableFile bool   `mapstructure:"enable_file"`
	FilePath   string `mapstructure:"file_path"`
}

// Field represents a log field
type Field struct {
	Key   string
	Value interface{}
}

// NewLogger creates a new logger instance
func NewLogger() *Logger {
	return NewLoggerWithConfig(&Config{
		Level:      "info",
		Format:     "json",
		Output:     "stdout",
		EnableFile: false,
		FilePath:   "/var/log/docker-security-scanner.log",
	})
}

// NewLoggerWithConfig creates a logger with specific configuration
func NewLoggerWithConfig(config *Config) *Logger {
	logger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Set formatter
	switch config.Format {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
				logrus.FieldKeyFunc:  "function",
				logrus.FieldKeyFile:  "file",
			},
		})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
			DisableColors:   true,
		})
	default:
		logger.SetFormatter(&logrus.JSONFormatter{})
	}

	// Set output
	outputs := []string{config.Output}
	if config.EnableFile && config.FilePath != "" {
		outputs = append(outputs, config.FilePath)
	}

	if len(outputs) > 1 {
		// Multiple outputs
		hooks := make(logrus.LevelHooks)
		for _, output := range outputs {
			hook, err := createFileHook(output)
			if err == nil {
				hooks.Add(hook)
			}
		}
		logger.Hooks = hooks
	} else {
		// Single output
		switch config.Output {
		case "stdout":
			logger.SetOutput(os.Stdout)
		case "stderr":
			logger.SetOutput(os.Stderr)
		default:
			if file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666); err == nil {
				logger.SetOutput(file)
			}
		}
	}

	return &Logger{
		Logger: logger,
		config: config,
	}
}

// WithField adds a single field to the logger
func (l *Logger) WithField(key string, value interface{}) *logrus.Entry {
	return l.Logger.WithField(key, value)
}

// WithFields adds multiple fields to the logger
func (l *Logger) WithFields(fields map[string]interface{}) *logrus.Entry {
	return l.Logger.WithFields(fields)
}

// WithError adds an error to the logger
func (l *Logger) WithError(err error) *logrus.Entry {
	return l.Logger.WithError(err)
}

// WithFieldsFromStruct adds fields from a struct
func (l *Logger) WithFieldsFromStruct(fields interface{}) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields{
		"struct": fields,
	})
}

// Debug logs a debug message
func (l *Logger) Debug(args ...interface{}) {
	l.Logger.Debug(args...)
}

// Debugf logs a debug message with formatting
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.Logger.Debugf(format, args...)
}

// Info logs an info message
func (l *Logger) Info(args ...interface{}) {
	l.Logger.Info(args...)
}

// Infof logs an info message with formatting
func (l *Logger) Infof(format string, args ...interface{}) {
	l.Logger.Infof(format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(args ...interface{}) {
	l.Logger.Warn(args...)
}

// Warnf logs a warning message with formatting
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.Logger.Warnf(format, args...)
}

// Error logs an error message
func (l *Logger) Error(args ...interface{}) {
	l.Logger.Error(args...)
}

// Errorf logs an error message with formatting
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.Logger.Errorf(format, args...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(args ...interface{}) {
	l.Logger.Fatal(args...)
}

// Fatalf logs a fatal message with formatting and exits
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.Logger.Fatalf(format, args...)
}

// Panic logs a panic message and panics
func (l *Logger) Panic(args ...interface{}) {
	l.Logger.Panic(args...)
}

// Panicf logs a panic message with formatting and panics
func (l *Logger) Panicf(format string, args ...interface{}) {
	l.Logger.Panicf(format, args...)
}

// Security logs a security-related message
func (l *Logger) Security(message string, fields ...Field) {
	entry := l.Logger.WithField("type", "security")
	for _, field := range fields {
		entry = entry.WithField(field.Key, field.Value)
	}
	entry.Info(message)
}

// Audit logs an audit-related message
func (l *Logger) Audit(message string, fields ...Field) {
	entry := l.Logger.WithFields(logrus.Fields{
		"type":      "audit",
		"timestamp": time.Now().Format(time.RFC3339),
	})
	for _, field := range fields {
		entry = entry.WithField(field.Key, field.Value)
	}
	entry.Info(message)
}

// Scan logs a scan-related message
func (l *Logger) Scan(message string, fields ...Field) {
	entry := l.Logger.WithField("type", "scan")
	for _, field := range fields {
		entry = entry.WithField(field.Key, field.Value)
	}
	entry.Info(message)
}

// Compliance logs a compliance-related message
func (l *Logger) Compliance(message string, fields ...Field) {
	entry := l.Logger.WithField("type", "compliance")
	for _, field := range fields {
		entry = entry.WithField(field.Key, field.Value)
	}
	entry.Info(message)
}

// Performance logs a performance-related message
func (l *Logger) Performance(message string, fields ...Field) {
	entry := l.Logger.WithField("type", "performance")
	for _, field := range fields {
		entry = entry.WithField(field.Key, field.Value)
	}
	entry.Info(message)
}

// WithCaller adds caller information to the logger
func (l *Logger) WithCaller() *logrus.Entry {
	_, file, line, ok := runtime.Caller(2)
	if ok {
		return l.Logger.WithFields(logrus.Fields{
			"file": filepath.Base(file),
			"line": line,
		})
	}
	return l.Logger.WithField("caller", "unknown")
}

// WithTrace adds trace information for debugging
func (l *Logger) WithTrace(traceID string) *logrus.Entry {
	return l.Logger.WithField("trace_id", traceID)
}

// WithRequest adds request information
func (l *Logger) WithRequest(requestID, method, path string) *logrus.Entry {
	return l.Logger.WithFields(logrus.Fields{
		"request_id": requestID,
		"method":     method,
		"path":       path,
	})
}

// LogScanStart logs the start of a security scan
func (l *Logger) LogScanStart(scanID string, target string, checkTypes []string) {
	l.WithFields(logrus.Fields{
		"event":     "scan_start",
		"scan_id":   scanID,
		"target":    target,
		"checks":    strings.Join(checkTypes, ","),
		"timestamp": time.Now().Format(time.RFC3339),
	}).Info("Security scan started")
}

// LogScanComplete logs the completion of a security scan
func (l *Logger) LogScanComplete(scanID string, duration time.Duration, issuesFound int) {
	l.WithFields(logrus.Fields{
		"event":        "scan_complete",
		"scan_id":      scanID,
		"duration_ms":  duration.Milliseconds(),
		"issues_found": issuesFound,
		"timestamp":    time.Now().Format(time.RFC3339),
	}).Info("Security scan completed")
}

// LogSecurityIssue logs a security issue found during scanning
func (l *Logger) LogSecurityIssue(scanID, containerID, issueType, severity string, details map[string]interface{}) {
	l.WithFields(logrus.Fields{
		"event":        "security_issue",
		"scan_id":      scanID,
		"container_id": containerID,
		"issue_type":   issueType,
		"severity":     severity,
		"details":      details,
		"timestamp":    time.Now().Format(time.RFC3339),
	}).Warn("Security issue detected")
}

// LogComplianceCheck logs compliance check results
func (l *Logger) LogComplianceCheck(scanID, framework, control string, passed bool, score float64) {
	level := logrus.InfoLevel
	if !passed {
		level = logrus.WarnLevel
	}

	l.WithFields(logrus.Fields{
		"event":      "compliance_check",
		"scan_id":    scanID,
		"framework":  framework,
		"control":    control,
		"passed":     passed,
		"score":      score,
		"timestamp":  time.Now().Format(time.RFC3339),
	}).Log(level, fmt.Sprintf("Compliance check %s: %s", framework, control))
}

// createFileHook creates a file hook for logging
func createFileHook(path string) (logrus.Hook, error) {
	if path == "stdout" {
		return &stdoutHook{}, nil
	}
	if path == "stderr" {
		return &stderrHook{}, nil
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	return &fileHook{file: file}, nil
}

// stdoutHook is a hook for stdout
type stdoutHook struct{}

func (h *stdoutHook) Fire(entry *logrus.Entry) error {
	fmt.Fprint(os.Stdout, entry.Message+"\n")
	return nil
}

func (h *stdoutHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// stderrHook is a hook for stderr
type stderrHook struct{}

func (h *stderrHook) Fire(entry *logrus.Entry) error {
	fmt.Fprint(os.Stderr, entry.Message+"\n")
	return nil
}

func (h *stderrHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// fileHook is a hook for file logging
type fileHook struct {
	file *os.File
}

func (h *fileHook) Fire(entry *logrus.Entry) error {
	_, err := fmt.Fprintln(h.file, entry.Message)
	return err
}

func (h *fileHook) Levels() []logrus.Level {
	return logrus.AllLevels
}