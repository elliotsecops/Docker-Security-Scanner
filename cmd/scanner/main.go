package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/elliotsecops/docker-security-scanner/internal/config"
	"github.com/elliotsecops/docker-security-scanner/internal/logging"
	"github.com/elliotsecops/docker-security-scanner/internal/scanner"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	logger := logging.NewLogger()
	logger.Info("Starting Docker Security Scanner")

	cfg, err := config.LoadConfig()
	if err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
	}

	// Start metrics server
	if cfg.Metrics.Enabled {
		go func() {
			http.Handle(cfg.Metrics.Path, promhttp.Handler())
			logger.WithField("port", cfg.Metrics.Port).Info("Starting metrics server")
			if err := http.ListenAndServe(cfg.Metrics.Port, nil); err != nil {
				logger.WithError(err).Error("Metrics server failed")
			}
		}()
	}

	secScanner := scanner.NewScanner(cfg, logger)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logger.Info("Starting security scan")
	results, err := secScanner.RunScan()
	if err != nil {
		logger.WithError(err).Error("Security scan failed")
	}

	if results != nil {
		if err := secScanner.GenerateReports(results); err != nil {
			logger.WithError(err).Error("Failed to generate reports")
		}

		fmt.Printf("Scan completed. Found %d issues across %d containers (Compliance: %.1f%%)\n",
			results.TotalIssues, results.ContainersScanned, results.ComplianceScore)
	}

	<-sigChan
	logger.Info("Received shutdown signal")
	logger.Info("Docker Security Scanner stopped")
}
