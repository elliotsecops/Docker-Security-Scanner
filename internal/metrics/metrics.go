package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the Docker Security Scanner
type Metrics struct {
	// Scan metrics
	ScansTotal           prometheus.Counter
	ScansFailed          prometheus.Counter
	ScanDuration         prometheus.Histogram
	ContainersScanned    prometheus.Counter
	ContainersFailed     prometheus.Counter

	// Security issue metrics
	SecurityIssuesTotal  prometheus.Counter
	SecurityIssuesByType *prometheus.CounterVec
	SecurityIssuesBySeverity *prometheus.CounterVec

	// Container metrics
	ContainersTotal      prometheus.Gauge
	ContainersRunning   prometheus.Gauge
	ContainersStopped   prometheus.Gauge
	ContainersByImage   *prometheus.GaugeVec

	// Performance metrics
	ScannerMemoryUsage  prometheus.Gauge
	ScannerCPUUsage      prometheus.Gauge
	ConcurrentScans     prometheus.Gauge
	QueueSize          prometheus.Gauge

	// Compliance metrics
	ComplianceScore     prometheus.Gauge
	CompliantContainers prometheus.Gauge
	NonCompliantContainers prometheus.Gauge

	// Docker metrics
	DockerAPIErrors     prometheus.Counter
	DockerResponseTime  prometheus.Histogram

	// Custom metrics for specific security checks
	RootUserContainers  prometheus.Gauge
	ExposedPortsCount   prometheus.Gauge
	VulnerableImages    prometheus.Gauge
	SecretsDetected     prometheus.Counter
}

// NewMetrics creates and initializes all Prometheus metrics
func NewMetrics() *Metrics {
	return &Metrics{
		// Scan metrics
		ScansTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "docker_security_scanner_scans_total",
			Help: "Total number of security scans performed",
		}),

		ScansFailed: promauto.NewCounter(prometheus.CounterOpts{
			Name: "docker_security_scanner_scans_failed_total",
			Help: "Total number of failed security scans",
		}),

		ScanDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "docker_security_scanner_scan_duration_seconds",
			Help:    "Duration of security scans in seconds",
			Buckets: prometheus.DefBuckets,
		}),

		ContainersScanned: promauto.NewCounter(prometheus.CounterOpts{
			Name: "docker_security_scanner_containers_scanned_total",
			Help: "Total number of containers scanned",
		}),

		ContainersFailed: promauto.NewCounter(prometheus.CounterOpts{
			Name: "docker_security_scanner_containers_failed_total",
			Help: "Total number of containers that failed to scan",
		}),

		// Security issue metrics
		SecurityIssuesTotal: promauto.NewCounter(prometheus.CounterOpts{
			Name: "docker_security_scanner_security_issues_total",
			Help: "Total number of security issues detected",
		}),

		SecurityIssuesByType: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "docker_security_scanner_security_issues_by_type_total",
			Help: "Security issues categorized by type",
		}, []string{"type"}),

		SecurityIssuesBySeverity: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "docker_security_scanner_security_issues_by_severity_total",
			Help: "Security issues categorized by severity",
		}, []string{"severity"}),

		// Container metrics
		ContainersTotal: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "docker_security_scanner_containers_total",
			Help: "Total number of containers",
		}),

		ContainersRunning: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "docker_security_scanner_containers_running",
			Help: "Number of running containers",
		}),

		ContainersStopped: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "docker_security_scanner_containers_stopped",
			Help: "Number of stopped containers",
		}),

		ContainersByImage: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "docker_security_scanner_containers_by_image",
			Help: "Number of containers by image",
		}, []string{"image"}),

		// Performance metrics
		ScannerMemoryUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "docker_security_scanner_memory_usage_bytes",
			Help: "Memory usage of the scanner in bytes",
		}),

		ScannerCPUUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "docker_security_scanner_cpu_usage_percent",
			Help: "CPU usage of the scanner in percent",
		}),

		ConcurrentScans: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "docker_security_scanner_concurrent_scans",
			Help: "Number of currently running scans",
		}),

		QueueSize: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "docker_security_scanner_queue_size",
			Help: "Number of containers in scan queue",
		}),

		// Compliance metrics
		ComplianceScore: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "docker_security_scanner_compliance_score",
			Help: "Overall compliance score (0-100)",
		}),

		CompliantContainers: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "docker_security_scanner_compliant_containers",
			Help: "Number of compliant containers",
		}),

		NonCompliantContainers: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "docker_security_scanner_non_compliant_containers",
			Help: "Number of non-compliant containers",
		}),

		// Docker metrics
		DockerAPIErrors: promauto.NewCounter(prometheus.CounterOpts{
			Name: "docker_security_scanner_docker_api_errors_total",
			Help: "Total number of Docker API errors",
		}),

		DockerResponseTime: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "docker_security_scanner_docker_response_time_seconds",
			Help:    "Docker API response time in seconds",
			Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1.0, 2.0, 5.0},
		}),

		// Custom security metrics
		RootUserContainers: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "docker_security_scanner_root_user_containers",
			Help: "Number of containers running as root user",
		}),

		ExposedPortsCount: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "docker_security_scanner_exposed_ports_total",
			Help: "Total number of exposed ports across all containers",
		}),

		VulnerableImages: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "docker_security_scanner_vulnerable_images",
			Help: "Number of images with known vulnerabilities",
		}),

		SecretsDetected: promauto.NewCounter(prometheus.CounterOpts{
			Name: "docker_security_scanner_secrets_detected_total",
			Help: "Total number of secrets detected",
		}),
	}
}

// RecordScanStart records metrics when a scan starts
func (m *Metrics) RecordScanStart() {
	m.ScansTotal.Inc()
	m.ConcurrentScans.Inc()
}

// RecordScanCompletion records metrics when a scan completes
func (m *Metrics) RecordScanCompletion(duration time.Duration, containersScanned, issuesFound int) {
	m.ScanDuration.Observe(duration.Seconds())
	m.ContainersScanned.Add(float64(containersScanned))
	m.SecurityIssuesTotal.Add(float64(issuesFound))
	m.ConcurrentScans.Dec()
}

// RecordScanFailure records metrics when a scan fails
func (m *Metrics) RecordScanFailure() {
	m.ScansFailed.Inc()
	m.ConcurrentScans.Dec()
}

// RecordSecurityIssue records a specific security issue
func (m *Metrics) RecordSecurityIssue(issueType, severity string) {
	m.SecurityIssuesByType.WithLabelValues(issueType).Inc()
	m.SecurityIssuesBySeverity.WithLabelValues(severity).Inc()
}

// UpdateContainerMetrics updates container-related metrics
func (m *Metrics) UpdateContainerMetrics(total, running, stopped int) {
	m.ContainersTotal.Set(float64(total))
	m.ContainersRunning.Set(float64(running))
	m.ContainersStopped.Set(float64(stopped))
}

// UpdateContainersByImage updates the count of containers by image
func (m *Metrics) UpdateContainersByImage(imageCounts map[string]int) {
	// Reset existing metrics
	m.ContainersByImage.Reset()

	// Set new values
	for image, count := range imageCounts {
		m.ContainersByImage.WithLabelValues(image).Set(float64(count))
	}
}

// UpdateComplianceMetrics updates compliance-related metrics
func (m *Metrics) UpdateComplianceMetrics(score float64, compliant, nonCompliant int) {
	m.ComplianceScore.Set(score)
	m.CompliantContainers.Set(float64(compliant))
	m.NonCompliantContainers.Set(float64(nonCompliant))
}

// UpdateSecurityMetrics updates security-specific metrics
func (m *Metrics) UpdateSecurityMetrics(rootUserCount, exposedPortsCount, vulnerableImages int) {
	m.RootUserContainers.Set(float64(rootUserCount))
	m.ExposedPortsCount.Set(float64(exposedPortsCount))
	m.VulnerableImages.Set(float64(vulnerableImages))
}

// RecordDockerAPIError records Docker API errors
func (m *Metrics) RecordDockerAPIError() {
	m.DockerAPIErrors.Inc()
}

// RecordDockerResponseTime records Docker API response time
func (m *Metrics) RecordDockerResponseTime(duration time.Duration) {
	m.DockerResponseTime.Observe(duration.Seconds())
}

// UpdatePerformanceMetrics updates performance-related metrics
func (m *Metrics) UpdatePerformanceMetrics(memoryUsage, cpuUsage float64, queueSize int) {
	m.ScannerMemoryUsage.Set(memoryUsage)
	m.ScannerCPUUsage.Set(cpuUsage)
	m.QueueSize.Set(float64(queueSize))
}

// RecordSecretDetection records when secrets are detected
func (m *Metrics) RecordSecretDetection(count int) {
	m.SecretsDetected.Add(float64(count))
}

// RecordContainerScanFailure records when a container fails to scan
func (m *Metrics) RecordContainerScanFailure() {
	m.ContainersFailed.Inc()
}

// GetMetricsSummary returns a summary of current metrics
func (m *Metrics) GetMetricsSummary() map[string]interface{} {
	return map[string]interface{}{
		"scans_total":           m.ScansTotal,
		"containers_total":      m.ContainersTotal,
		"containers_running":    m.ContainersRunning,
		"security_issues_total": m.SecurityIssuesTotal,
		"compliance_score":      m.ComplianceScore,
		"concurrent_scans":      m.ConcurrentScans,
	}
}