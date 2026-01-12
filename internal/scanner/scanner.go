package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/elliotsecops/docker-security-scanner/internal/checks"
	"github.com/elliotsecops/docker-security-scanner/internal/config"
	"github.com/elliotsecops/docker-security-scanner/internal/errors"
	"github.com/elliotsecops/docker-security-scanner/internal/logging"
	"github.com/elliotsecops/docker-security-scanner/internal/metrics"
)

type DockerClient = checks.DockerClient
type DockerContainer = checks.DockerContainer
type DockerContainerDetails = checks.DockerContainerDetails
type ContainerConfig = checks.ContainerConfig
type HostConfig = checks.HostConfig
type SecurityCheck = checks.SecurityCheck
type SecurityCheckResult = checks.SecurityCheckResult
type Severity = checks.Severity
type Category = checks.Category
type PortBinding = checks.PortBinding

type Scanner struct {
	config         *config.Config
	logger         *logging.Logger
	dockerClient   DockerClient
	checks         []SecurityCheck
	errorCollector *errors.ErrorCollector
	metrics        *metrics.Metrics
}

type ScanResult struct {
	ScanID            string                      `json:"scan_id"`
	Timestamp         time.Time                   `json:"timestamp"`
	Duration          time.Duration               `json:"duration"`
	ContainersScanned int                         `json:"containers_scanned"`
	TotalIssues       int                         `json:"total_issues"`
	TotalCritical     int                         `json:"total_critical"`
	TotalHigh         int                         `json:"total_high"`
	TotalMedium       int                         `json:"total_medium"`
	TotalLow          int                         `json:"total_low"`
	ContainerResults  map[string]*ContainerResult `json:"container_results"`
	ComplianceScore   float64                     `json:"compliance_score"`
	Summary           *ScanSummary                `json:"summary"`
}

type ContainerResult struct {
	ContainerID     string                 `json:"container_id"`
	ContainerName   string                 `json:"container_name"`
	Image           string                 `json:"image"`
	Status          string                 `json:"status"`
	ScanResults     []*SecurityCheckResult `json:"scan_results"`
	Score           float64                `json:"score"`
	HighRiskCount   int                    `json:"high_risk_count"`
	MediumRiskCount int                    `json:"medium_risk_count"`
	LowRiskCount    int                    `json:"low_risk_count"`
	Timestamp       time.Time              `json:"timestamp"`
}

type ScanSummary struct {
	TotalContainers        int      `json:"total_containers"`
	CompliantContainers    int      `json:"compliant_containers"`
	NonCompliantContainers int      `json:"non_compliant_containers"`
	CriticalIssues         int      `json:"critical_issues"`
	HighIssues             int      `json:"high_issues"`
	MediumIssues           int      `json:"medium_issues"`
	LowIssues              int      `json:"low_issues"`
	ComplianceScore        float64  `json:"compliance_score"`
	Recommendations        []string `json:"recommendations"`
}

func NewDockerClient(config config.DockerConfig) DockerClient {
	return &dockerClientImpl{
		socketPath: config.SocketPath,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", config.SocketPath)
				},
			},
		},
	}
}

type dockerClientImpl struct {
	socketPath string
	client     *http.Client
}

func (d *dockerClientImpl) ListContainers(ctx context.Context, all bool) ([]*DockerContainer, error) {
	url := "http://docker/containers/json"
	if all {
		url += "?all=1"
	}

	resp, err := d.client.Get(url)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeNetwork, "failed to list containers")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.NewDocker(fmt.Sprintf("failed to list containers, status code: %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "failed to read response body")
	}

	var containers []*DockerContainer
	if err := json.Unmarshal(body, &containers); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "failed to unmarshal JSON")
	}

	return containers, nil
}

func (d *dockerClientImpl) InspectContainer(ctx context.Context, containerID string) (*DockerContainerDetails, error) {
	url := fmt.Sprintf("http://docker/containers/%s/json", containerID)

	resp, err := d.client.Get(url)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeNetwork, "failed to inspect container")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.NewDocker(fmt.Sprintf("failed to inspect container, status code: %d", resp.StatusCode))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "failed to read response body")
	}

	var details DockerContainerDetails
	if err := json.Unmarshal(body, &details); err != nil {
		return nil, errors.Wrap(err, errors.ErrorTypeInternal, "failed to unmarshal JSON")
	}

	return &details, nil
}

func NewScanner(cfg *config.Config, logger *logging.Logger) *Scanner {
	return NewScannerWithMetrics(cfg, logger, metrics.NewMetrics())
}

func NewScannerWithMetrics(cfg *config.Config, logger *logging.Logger, metricsCollector *metrics.Metrics) *Scanner {
	dockerClient := NewDockerClient(cfg.Docker)

	scanner := &Scanner{
		config:         cfg,
		logger:         logger,
		dockerClient:   dockerClient,
		errorCollector: errors.NewErrorCollector(),
		metrics:        metricsCollector,
	}

	scanner.initializeChecks()

	return scanner
}

func (s *Scanner) RunScan() (*ScanResult, error) {
	scanID := generateScanID()
	startTime := time.Now()

	if s.metrics != nil {
		s.metrics.RecordScanStart()
	}

	s.logger.LogScanStart(scanID, "docker-containers", s.getCheckTypes())

	ctx, cancel := context.WithTimeout(context.Background(), getDuration(s.config.Scanner.Timeout))
	defer cancel()

	containers, err := s.getContainersToScan(ctx)
	if err != nil {
		if s.metrics != nil {
			s.metrics.RecordDockerAPIError()
		}
		return nil, errors.Wrap(err, errors.ErrorTypeDocker, "failed to get containers")
	}

	s.logger.WithField("container_count", len(containers)).Info("Retrieved containers for scanning")

	if s.metrics != nil {
		s.updateContainerMetrics(containers)
	}

	results := s.scanContainers(ctx, containers, scanID)

	scanResult := s.generateScanResult(scanID, startTime, results)

	s.logger.LogScanComplete(scanID, time.Since(startTime), scanResult.TotalIssues)

	if s.metrics != nil {
		s.metrics.RecordScanCompletion(time.Since(startTime), scanResult.ContainersScanned, scanResult.TotalIssues)
		s.updateSecurityMetrics(scanResult)
	}

	return scanResult, nil
}

func (s *Scanner) initializeChecks() {
	s.checks = make([]SecurityCheck, 0)

	if s.config.SecurityChecks.RootUserCheck {
		s.checks = append(s.checks, checks.NewRootUserCheck())
	}

	if s.config.SecurityChecks.ExposedPortsCheck {
		s.checks = append(s.checks, checks.NewExposedPortsCheck())
	}

	if s.config.SecurityChecks.VulnerabilityCheck {
		s.checks = append(s.checks, checks.NewVulnerabilityCheckWithConfig(nil))
	}

	if s.config.SecurityChecks.SecretsCheck {
		s.checks = append(s.checks, checks.NewSecretsCheck())
	}

	if s.config.SecurityChecks.NetworkPolicyCheck {
		s.checks = append(s.checks, checks.NewNetworkPolicyCheck())
	}

	if s.config.SecurityChecks.ResourceLimitsCheck {
		s.checks = append(s.checks, checks.NewResourceLimitsCheck())
	}

	if s.config.SecurityChecks.ImageIntegrityCheck {
		s.checks = append(s.checks, checks.NewImageIntegrityCheck())
	}

	if s.config.SecurityChecks.ProcessMonitoringCheck {
		s.checks = append(s.checks, checks.NewProcessMonitoringCheck())
	}

	s.logger.WithField("check_count", len(s.checks)).Info("Initialized security checks")
}

func (s *Scanner) getContainersToScan(ctx context.Context) ([]*DockerContainer, error) {
	allContainers, err := s.dockerClient.ListContainers(ctx, s.config.Scanner.ScanStopped)
	if err != nil {
		return nil, err
	}

	var filteredContainers []*DockerContainer
	for _, container := range allContainers {
		if s.shouldScanContainer(container) {
			filteredContainers = append(filteredContainers, container)
		}
	}

	return filteredContainers, nil
}

func (s *Scanner) shouldScanContainer(container *DockerContainer) bool {
	for _, excludeImage := range s.config.Scanner.ExcludeImages {
		if contains(container.Image, excludeImage) {
			s.logger.WithField("container_id", container.ID).Debug("Skipping container - image excluded")
			return false
		}
	}

	for _, excludeName := range s.config.Scanner.ExcludeNames {
		for _, name := range container.Names {
			if contains(name, excludeName) {
				s.logger.WithField("container_id", container.ID).Debug("Skipping container - name excluded")
				return false
			}
		}
	}

	return true
}

func (s *Scanner) scanContainers(ctx context.Context, containers []*DockerContainer, scanID string) map[string]*ContainerResult {
	results := make(map[string]*ContainerResult)
	var mu sync.Mutex

	workerPool := make(chan struct{}, s.config.Scanner.MaxConcurrentScans)
	for i := 0; i < s.config.Scanner.MaxConcurrentScans; i++ {
		workerPool <- struct{}{}
	}

	var wg sync.WaitGroup

	for _, container := range containers {
		wg.Add(1)
		go func(container *DockerContainer) {
			defer wg.Done()

			<-workerPool
			defer func() { workerPool <- struct{}{} }()

			containerResult := s.scanSingleContainer(ctx, container, scanID)

			mu.Lock()
			results[container.ID] = containerResult
			mu.Unlock()
		}(container)
	}

	wg.Wait()
	return results
}

func (s *Scanner) scanSingleContainer(ctx context.Context, container *DockerContainer, scanID string) *ContainerResult {
	s.logger.WithField("container_id", container.ID).Info("Scanning container")

	result := &ContainerResult{
		ContainerID:   container.ID,
		ContainerName: getContainerName(container.Names),
		Image:         container.Image,
		Status:        container.State,
		Timestamp:     time.Now(),
	}

	for _, check := range s.checks {
		checkResult, err := check.Execute(ctx, container, s.dockerClient)
		if err != nil {
			s.errorCollector.Add(errors.Wrap(err, errors.ErrorTypeSecurity, "security check failed"))
			continue
		}

		result.ScanResults = append(result.ScanResults, checkResult)

		if !checkResult.Passed {
			s.logger.LogSecurityIssue(scanID, container.ID, checkResult.CheckName, string(checkResult.Severity), checkResult.Details)
		}

		switch checkResult.Severity {
		case checks.SeverityCritical, checks.SeverityHigh:
			result.HighRiskCount++
		case checks.SeverityMedium:
			result.MediumRiskCount++
		case checks.SeverityLow:
			result.LowRiskCount++
		}
	}

	result.Score = s.calculateContainerScore(result)

	s.logger.WithFields(map[string]interface{}{
		"container_id": container.ID,
		"score":        result.Score,
		"issues_found": len(result.ScanResults),
	}).Info("Container scan completed")

	return result
}

func (s *Scanner) generateScanResult(scanID string, startTime time.Time, containerResults map[string]*ContainerResult) *ScanResult {
	result := &ScanResult{
		ScanID:            scanID,
		Timestamp:         startTime,
		Duration:          time.Since(startTime),
		ContainerResults:  containerResults,
		ContainersScanned: len(containerResults),
	}

	for _, containerResult := range containerResults {
		result.TotalCritical += containerResult.HighRiskCount
		result.TotalHigh += containerResult.HighRiskCount
		result.TotalMedium += containerResult.MediumRiskCount
		result.TotalLow += containerResult.LowRiskCount

		for _, checkResult := range containerResult.ScanResults {
			if !checkResult.Passed {
				result.TotalIssues++
			}
		}
	}

	result.Summary = s.generateScanSummary(containerResults)
	result.ComplianceScore = s.calculateComplianceScore(containerResults)

	return result
}

func (s *Scanner) generateScanSummary(containerResults map[string]*ContainerResult) *ScanSummary {
	summary := &ScanSummary{
		TotalContainers:        len(containerResults),
		CompliantContainers:    0,
		NonCompliantContainers: 0,
		CriticalIssues:         0,
		HighIssues:             0,
		MediumIssues:           0,
		LowIssues:              0,
	}

	for _, containerResult := range containerResults {
		if containerResult.HighRiskCount == 0 {
			summary.CompliantContainers++
		} else {
			summary.NonCompliantContainers++
		}

		summary.CriticalIssues += containerResult.HighRiskCount
		summary.HighIssues += containerResult.HighRiskCount
		summary.MediumIssues += containerResult.MediumRiskCount
		summary.LowIssues += containerResult.LowRiskCount
	}

	summary.Recommendations = s.generateRecommendations(summary)

	return summary
}

func (s *Scanner) calculateContainerScore(result *ContainerResult) float64 {
	if len(result.ScanResults) == 0 {
		return 100.0
	}

	totalWeight := 0.0
	passedWeight := 0.0

	for _, checkResult := range result.ScanResults {
		weight := getSeverityWeight(checkResult.Severity)
		totalWeight += weight

		if checkResult.Passed {
			passedWeight += weight
		}
	}

	if totalWeight == 0 {
		return 100.0
	}

	return (passedWeight / totalWeight) * 100
}

func (s *Scanner) calculateComplianceScore(containerResults map[string]*ContainerResult) float64 {
	if len(containerResults) == 0 {
		return 100.0
	}

	totalScore := 0.0
	for _, containerResult := range containerResults {
		totalScore += containerResult.Score
	}

	return totalScore / float64(len(containerResults))
}

func (s *Scanner) generateRecommendations(summary *ScanSummary) []string {
	var recommendations []string

	if summary.CriticalIssues > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Address %d critical security issues immediately", summary.CriticalIssues))
	}

	if summary.HighIssues > 0 {
		recommendations = append(recommendations, fmt.Sprintf("Review and fix %d high-severity security issues", summary.HighIssues))
	}

	if summary.NonCompliantContainers > 0 {
		recommendations = append(recommendations, "Implement security hardening for non-compliant containers")
	}

	if summary.MediumIssues > 0 {
		recommendations = append(recommendations, "Address medium-severity issues in next security update")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "No security issues detected - maintain current security posture")
	}

	return recommendations
}

func (s *Scanner) getCheckTypes() []string {
	types := make([]string, len(s.checks))
	for i, check := range s.checks {
		types[i] = string(check.Category())
	}
	return types
}

func (s *Scanner) GetErrorCollector() *errors.ErrorCollector {
	return s.errorCollector
}

func (s *Scanner) GetChecks() []SecurityCheck {
	return s.checks
}

func (s *Scanner) GenerateReports(results *ScanResult) error {
	s.logger.Info("Generating reports...")

	if s.containsFormat("json") {
		if err := s.generateJSONReport(results); err != nil {
			return err
		}
	}

	if s.containsFormat("csv") {
		if err := s.generateCSVReport(results); err != nil {
			return err
		}
	}

	s.logger.Info("Reports generated successfully")
	return nil
}

func (s *Scanner) containsFormat(format string) bool {
	for _, f := range s.config.Reporting.Formats {
		if f == format {
			return true
		}
	}
	return false
}

func (s *Scanner) generateJSONReport(results *ScanResult) error {
	reportPath := filepath.Join(s.config.Reporting.OutputDir, fmt.Sprintf("scan-report-%s.json", results.ScanID))

	file, err := os.Create(reportPath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("failed to encode JSON report: %w", err)
	}

	s.logger.WithField("report_path", reportPath).Info("JSON report generated successfully")
	return nil
}

func (s *Scanner) generateCSVReport(results *ScanResult) error {
	reportPath := filepath.Join(s.config.Reporting.OutputDir, fmt.Sprintf("scan-report-%s.csv", results.ScanID))

	file, err := os.Create(reportPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV report file: %w", err)
	}
	defer file.Close()

	if _, err := file.WriteString("Container ID,Container Name,Image,Check Name,Severity,Passed,Details\n"); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for containerID, containerResult := range results.ContainerResults {
		for _, checkResult := range containerResult.ScanResults {
			details := fmt.Sprintf("%v", checkResult.Details)
			details = strings.ReplaceAll(details, "\"", "\"\"")

			line := fmt.Sprintf("%s,%s,%s,%s,%s,%t,\"%s\"\n",
				containerID,
				escapeCSV(containerResult.ContainerName),
				escapeCSV(containerResult.Image),
				escapeCSV(checkResult.CheckName),
				checkResult.Severity,
				checkResult.Passed,
				details,
			)

			if _, err := file.WriteString(line); err != nil {
				return fmt.Errorf("failed to write CSV row: %w", err)
			}
		}
	}

	s.logger.WithField("report_path", reportPath).Info("CSV report generated successfully")
	return nil
}

func escapeCSV(s string) string {
	if strings.Contains(s, ",") || strings.Contains(s, "\"") || strings.Contains(s, "\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func generateScanID() string {
	return fmt.Sprintf("scan-%d", time.Now().Unix())
}

func getDuration(durationStr string) time.Duration {
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return 30 * time.Minute
	}
	return duration
}

func getContainerName(names []string) string {
	if len(names) == 0 {
		return "unnamed"
	}
	return names[0]
}

func getSeverityWeight(severity checks.Severity) float64 {
	switch severity {
	case checks.SeverityCritical:
		return 3.0
	case checks.SeverityHigh:
		return 2.5
	case checks.SeverityMedium:
		return 2.0
	case checks.SeverityLow:
		return 1.0
	default:
		return 1.0
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && s[:len(substr)+1] == substr+":"))
}

func (s *Scanner) updatePerformanceMetrics()                            {}
func (s *Scanner) updateContainerMetrics(containers []*DockerContainer) {}
func (s *Scanner) updateSecurityMetrics(scanResult *ScanResult)         {}
