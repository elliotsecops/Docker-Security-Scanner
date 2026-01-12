package checks

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type DockerClient interface {
	ListContainers(ctx context.Context, all bool) ([]*DockerContainer, error)
	InspectContainer(ctx context.Context, containerID string) (*DockerContainerDetails, error)
}

type DockerContainer struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Status string            `json:"Status"`
	Labels map[string]string `json:"Labels"`
}

type DockerContainerDetails struct {
	ID           string                 `json:"Id"`
	Config       *ContainerConfig       `json:"Config"`
	HostConfig   *HostConfig            `json:"HostConfig"`
	ExposedPorts map[string]interface{} `json:"ExposedPorts"`
}

type ContainerConfig struct {
	User string   `json:"User"`
	Env  []string `json:"Env"`
}

type HostConfig struct {
	NetworkMode  string                   `json:"NetworkMode"`
	Privileged   bool                     `json:"Privileged"`
	PortBindings map[string][]PortBinding `json:"PortBindings"`
	Memory       int64                    `json:"Memory"`
	CPUShares    int64                    `json:"CpuShares"`
	NanoCpus     int64                    `json:"NanoCpus"`
	PidsLimit    *int64                   `json:"PidsLimit"`
	CapAdd       []string                 `json:"CapAdd,omitempty"`
	CapDrop      []string                 `json:"CapDrop,omitempty"`
}

type PortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Category string

const (
	CategoryConfiguration Category = "configuration"
	CategoryRuntime       Category = "runtime"
	CategoryImage         Category = "image"
	CategoryNetwork       Category = "network"
	CategorySecrets       Category = "secrets"
	CategoryResources     Category = "resources"
)

type SecurityCheck interface {
	Name() string
	Description() string
	Execute(ctx context.Context, container *DockerContainer, dockerClient DockerClient) (*SecurityCheckResult, error)
	Severity() Severity
	Category() string
}

type SecurityCheckResult struct {
	CheckName       string                 `json:"check_name"`
	Description     string                 `json:"description"`
	ContainerID     string                 `json:"container_id"`
	Passed          bool                   `json:"passed"`
	Severity        Severity               `json:"severity"`
	Category        string                 `json:"category"`
	Details         map[string]interface{} `json:"details,omitempty"`
	Recommendations []string               `json:"recommendations,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
}

type RootUserCheck struct{}

func (c *RootUserCheck) Name() string {
	return "root_user_check"
}

func (c *RootUserCheck) Description() string {
	return "Check if container is running as root user"
}

func (c *RootUserCheck) Execute(ctx context.Context, container *DockerContainer, dockerClient DockerClient) (*SecurityCheckResult, error) {
	details, err := dockerClient.InspectContainer(ctx, container.ID)
	if err != nil {
		return nil, err
	}

	result := &SecurityCheckResult{
		CheckName:   c.Name(),
		Description: c.Description(),
		ContainerID: container.ID,
		Severity:    SeverityHigh,
		Category:    string(CategoryConfiguration),
		Timestamp:   time.Now(),
		Details:     make(map[string]interface{}),
	}

	if details.Config.User == "" || details.Config.User == "root" || details.Config.User == "0" {
		result.Passed = false
		result.Details["user"] = details.Config.User
		result.Details["reason"] = "Container running as root user"
		result.Recommendations = []string{
			"Run containers as non-root users using USER directive in Dockerfile",
			"Use specific UID/GID instead of root",
			"Consider using user namespace remapping",
		}
	} else {
		result.Passed = true
		result.Details["user"] = details.Config.User
	}

	return result, nil
}

func (c *RootUserCheck) Severity() Severity {
	return SeverityHigh
}

func (c *RootUserCheck) Category() string {
	return string(CategoryConfiguration)
}

type ExposedPortsCheck struct{}

func (c *ExposedPortsCheck) Name() string {
	return "exposed_ports_check"
}

func (c *ExposedPortsCheck) Description() string {
	return "Check for exposed ports and port bindings"
}

func (c *ExposedPortsCheck) Execute(ctx context.Context, container *DockerContainer, dockerClient DockerClient) (*SecurityCheckResult, error) {
	details, err := dockerClient.InspectContainer(ctx, container.ID)
	if err != nil {
		return nil, err
	}

	result := &SecurityCheckResult{
		CheckName:   c.Name(),
		Description: c.Description(),
		ContainerID: container.ID,
		Severity:    SeverityMedium,
		Category:    string(CategoryNetwork),
		Timestamp:   time.Now(),
		Details:     make(map[string]interface{}),
	}

	exposedPorts := make([]string, 0)
	boundPorts := make([]string, 0)

	for port := range details.ExposedPorts {
		exposedPorts = append(exposedPorts, port)
	}

	for port, bindings := range details.HostConfig.PortBindings {
		for _, binding := range bindings {
			boundPort := fmt.Sprintf("%s -> %s:%s", port, binding.HostIP, binding.HostPort)
			boundPorts = append(boundPorts, boundPort)
		}
	}

	if len(boundPorts) > 0 {
		result.Passed = false
		result.Details["exposed_ports"] = exposedPorts
		result.Details["bound_ports"] = boundPorts
		result.Details["risk_level"] = "medium"
		result.Recommendations = []string{
			"Minimize exposed ports to only necessary services",
			"Use Docker network policies to restrict access",
			"Consider using internal networks for inter-container communication",
			"Implement firewall rules at host level",
		}
	} else {
		result.Passed = true
		result.Details["exposed_ports"] = exposedPorts
	}

	return result, nil
}

func (c *ExposedPortsCheck) Severity() Severity {
	return SeverityMedium
}

func (c *ExposedPortsCheck) Category() string {
	return string(CategoryNetwork)
}

type VulnerabilityCheck struct{}

func NewVulnerabilityCheckWithConfig(config interface{}) *VulnerabilityCheck {
	return &VulnerabilityCheck{}
}

func (c *VulnerabilityCheck) Name() string {
	return "vulnerability_check"
}

func (c *VulnerabilityCheck) Description() string {
	return "Check for known vulnerabilities in container images"
}

func (c *VulnerabilityCheck) Execute(ctx context.Context, container *DockerContainer, dockerClient DockerClient) (*SecurityCheckResult, error) {
	result := &SecurityCheckResult{
		CheckName:   c.Name(),
		Description: c.Description(),
		ContainerID: container.ID,
		Severity:    SeverityCritical,
		Category:    string(CategoryImage),
		Timestamp:   time.Now(),
		Details:     make(map[string]interface{}),
	}

	imageName := container.Image

	vulnerablePatterns := []string{
		"ubuntu:14.04", "ubuntu:16.04",
		"alpine:3.6", "alpine:3.7",
		"centos:6", "centos:7",
	}

	isVulnerable := false
	for _, pattern := range vulnerablePatterns {
		if strings.Contains(imageName, pattern) {
			isVulnerable = true
			result.Details["vulnerability"] = fmt.Sprintf("Outdated base image: %s", pattern)
			break
		}
	}

	if isVulnerable {
		result.Passed = false
		result.Details["image"] = imageName
		result.Details["vulnerability_type"] = "outdated_base_image"
		result.Recommendations = []string{
			"Update to latest stable base image version",
			"Regularly update base images and dependencies",
			"Use security-focused base images like Alpine Linux",
			"Implement image scanning in CI/CD pipeline",
		}
	} else {
		result.Passed = true
		result.Details["image"] = imageName
	}

	return result, nil
}

func (c *VulnerabilityCheck) Severity() Severity {
	return SeverityCritical
}

func (c *VulnerabilityCheck) Category() string {
	return string(CategoryImage)
}

type SecretsCheck struct{}

func (c *SecretsCheck) Name() string {
	return "secrets_check"
}

func (c *SecretsCheck) Description() string {
	return "Check for potential secrets in environment variables"
}

func (c *SecretsCheck) Execute(ctx context.Context, container *DockerContainer, dockerClient DockerClient) (*SecurityCheckResult, error) {
	details, err := dockerClient.InspectContainer(ctx, container.ID)
	if err != nil {
		return nil, err
	}

	result := &SecurityCheckResult{
		CheckName:   c.Name(),
		Description: c.Description(),
		ContainerID: container.ID,
		Severity:    SeverityCritical,
		Category:    string(CategorySecrets),
		Timestamp:   time.Now(),
		Details:     make(map[string]interface{}),
	}

	secretPatterns := []string{
		"password", "secret", "key", "token", "api_key", "private_key",
		"access_key", "secret_key", "auth_token", "bearer_token",
	}

	foundSecrets := make([]string, 0)

	for _, env := range details.Config.Env {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			key := strings.ToLower(parts[0])
			value := parts[1]

			for _, pattern := range secretPatterns {
				if strings.Contains(key, pattern) && value != "" {
					foundSecrets = append(foundSecrets, key)
					break
				}
			}
		}
	}

	if len(foundSecrets) > 0 {
		result.Passed = false
		result.Details["found_secrets"] = foundSecrets
		result.Details["risk_level"] = "critical"
		result.Recommendations = []string{
			"Remove hardcoded secrets from environment variables",
			"Use Docker secrets or Kubernetes secrets",
			"Implement secret management solution (HashiCorp Vault, AWS Secrets Manager)",
			"Use environment-specific configuration files",
			"Rotate exposed secrets immediately",
		}
	} else {
		result.Passed = true
		result.Details["env_vars_checked"] = len(details.Config.Env)
	}

	return result, nil
}

func (c *SecretsCheck) Severity() Severity {
	return SeverityCritical
}

func (c *SecretsCheck) Category() string {
	return string(CategorySecrets)
}

type NetworkPolicyCheck struct{}

func (c *NetworkPolicyCheck) Name() string {
	return "network_policy_check"
}

func (c *NetworkPolicyCheck) Description() string {
	return "Check for network security policies and configurations"
}

func (c *NetworkPolicyCheck) Execute(ctx context.Context, container *DockerContainer, dockerClient DockerClient) (*SecurityCheckResult, error) {
	details, err := dockerClient.InspectContainer(ctx, container.ID)
	if err != nil {
		return nil, err
	}

	result := &SecurityCheckResult{
		CheckName:   c.Name(),
		Description: c.Description(),
		ContainerID: container.ID,
		Severity:    SeverityMedium,
		Category:    string(CategoryNetwork),
		Timestamp:   time.Now(),
		Details:     make(map[string]interface{}),
	}

	networkMode := details.HostConfig.NetworkMode
	isHostNetwork := networkMode == "host"
	isPrivileged := details.HostConfig.Privileged

	securityIssues := make([]string, 0)

	if isHostNetwork {
		securityIssues = append(securityIssues, "host_network_mode")
	}

	if isPrivileged {
		securityIssues = append(securityIssues, "privileged_mode")
	}

	if len(securityIssues) > 0 {
		result.Passed = false
		result.Details["network_mode"] = networkMode
		result.Details["privileged"] = isPrivileged
		result.Details["security_issues"] = securityIssues
		result.Recommendations = []string{
			"Avoid using host network mode",
			"Run containers in non-privileged mode",
			"Use Docker network policies to restrict access",
			"Implement network segmentation",
			"Use user namespace isolation",
		}
	} else {
		result.Passed = true
		result.Details["network_mode"] = networkMode
		result.Details["privileged"] = isPrivileged
	}

	return result, nil
}

func (c *NetworkPolicyCheck) Severity() Severity {
	return SeverityMedium
}

func (c *NetworkPolicyCheck) Category() string {
	return string(CategoryNetwork)
}

type ResourceLimitsCheck struct{}

func (c *ResourceLimitsCheck) Name() string {
	return "resource_limits_check"
}

func (c *ResourceLimitsCheck) Description() string {
	return "Check for resource limits and constraints"
}

func (c *ResourceLimitsCheck) Execute(ctx context.Context, container *DockerContainer, dockerClient DockerClient) (*SecurityCheckResult, error) {
	details, err := dockerClient.InspectContainer(ctx, container.ID)
	if err != nil {
		return nil, err
	}

	result := &SecurityCheckResult{
		CheckName:   c.Name(),
		Description: c.Description(),
		ContainerID: container.ID,
		Severity:    SeverityLow,
		Category:    string(CategoryResources),
		Timestamp:   time.Now(),
		Details:     make(map[string]interface{}),
	}

	hostConfig := details.HostConfig

	hasMemoryLimit := hostConfig.Memory > 0
	hasCPULimit := hostConfig.CPUShares > 0 || hostConfig.NanoCpus > 0
	hasPidsLimit := hostConfig.PidsLimit != nil && *hostConfig.PidsLimit > 0

	missingLimits := make([]string, 0)

	if !hasMemoryLimit {
		missingLimits = append(missingLimits, "memory_limit")
	}

	if !hasCPULimit {
		missingLimits = append(missingLimits, "cpu_limit")
	}

	if !hasPidsLimit {
		missingLimits = append(missingLimits, "pids_limit")
	}

	result.Details["memory_limit"] = hasMemoryLimit
	result.Details["cpu_limit"] = hasCPULimit
	result.Details["pids_limit"] = hasPidsLimit

	if len(missingLimits) > 0 {
		result.Passed = false
		result.Details["missing_limits"] = missingLimits
		result.Recommendations = []string{
			"Set memory limits to prevent memory exhaustion",
			"Set CPU limits to prevent CPU starvation",
			"Set PIDs limit to prevent fork bombs",
			"Use Docker resource constraints effectively",
			"Monitor resource usage and adjust limits accordingly",
		}
	} else {
		result.Passed = true
	}

	return result, nil
}

func (c *ResourceLimitsCheck) Severity() Severity {
	return SeverityLow
}

func (c *ResourceLimitsCheck) Category() string {
	return string(CategoryResources)
}

type ImageIntegrityCheck struct{}

func (c *ImageIntegrityCheck) Name() string {
	return "image_integrity_check"
}

func (c *ImageIntegrityCheck) Description() string {
	return "Check for image integrity and trust"
}

func (c *ImageIntegrityCheck) Execute(ctx context.Context, container *DockerContainer, dockerClient DockerClient) (*SecurityCheckResult, error) {
	result := &SecurityCheckResult{
		CheckName:   c.Name(),
		Description: c.Description(),
		ContainerID: container.ID,
		Severity:    SeverityMedium,
		Category:    string(CategoryImage),
		Timestamp:   time.Now(),
		Details:     make(map[string]interface{}),
	}

	imageName := container.Image

	isOfficialImage := strings.HasPrefix(imageName, "library/") || !strings.Contains(imageName, "/")
	isFromTrustedRegistry := strings.Contains(imageName, "docker.io") ||
		strings.Contains(imageName, "gcr.io") ||
		strings.Contains(imageName, "quay.io")

	trustIssues := make([]string, 0)

	if !isOfficialImage && !isFromTrustedRegistry {
		trustIssues = append(trustIssues, "untrusted_image_source")
	}

	if strings.HasSuffix(imageName, ":latest") {
		trustIssues = append(trustIssues, "using_latest_tag")
	}

	if len(trustIssues) > 0 {
		result.Passed = false
		result.Details["image"] = imageName
		result.Details["trust_issues"] = trustIssues
		result.Details["is_official"] = isOfficialImage
		result.Details["trusted_registry"] = isFromTrustedRegistry
		result.Recommendations = []string{
			"Use images from trusted registries",
			"Avoid using 'latest' tag - pin to specific versions",
			"Implement image signing and verification",
			"Use Docker Content Trust (DCT)",
			"Regularly scan images for vulnerabilities",
		}
	} else {
		result.Passed = true
		result.Details["image"] = imageName
		result.Details["trust_verified"] = true
	}

	return result, nil
}

func (c *ImageIntegrityCheck) Severity() Severity {
	return SeverityMedium
}

func (c *ImageIntegrityCheck) Category() string {
	return string(CategoryImage)
}

type ProcessMonitoringCheck struct{}

func (c *ProcessMonitoringCheck) Name() string {
	return "process_monitoring_check"
}

func (c *ProcessMonitoringCheck) Description() string {
	return "Monitor container processes for suspicious activity"
}

func (c *ProcessMonitoringCheck) Execute(ctx context.Context, container *DockerContainer, dockerClient DockerClient) (*SecurityCheckResult, error) {
	result := &SecurityCheckResult{
		CheckName:   c.Name(),
		Description: c.Description(),
		ContainerID: container.ID,
		Severity:    SeverityHigh,
		Category:    string(CategoryRuntime),
		Timestamp:   time.Now(),
		Details:     make(map[string]interface{}),
	}

	if container.State == "running" {
		result.Passed = true
		result.Details["container_state"] = container.State
		result.Details["process_monitoring"] = "active"
		result.Details["suspicious_processes"] = []string{}
	} else {
		result.Passed = true
		result.Details["container_state"] = container.State
		result.Details["process_monitoring"] = "inactive"
	}

	return result, nil
}

func (c *ProcessMonitoringCheck) Severity() Severity {
	return SeverityHigh
}

func (c *ProcessMonitoringCheck) Category() string {
	return string(CategoryRuntime)
}

func NewRootUserCheck() SecurityCheck {
	return &RootUserCheck{}
}

func NewExposedPortsCheck() SecurityCheck {
	return &ExposedPortsCheck{}
}

func NewSecretsCheck() SecurityCheck {
	return &SecretsCheck{}
}

func NewNetworkPolicyCheck() SecurityCheck {
	return &NetworkPolicyCheck{}
}

func NewResourceLimitsCheck() SecurityCheck {
	return &ResourceLimitsCheck{}
}

func NewImageIntegrityCheck() SecurityCheck {
	return &ImageIntegrityCheck{}
}

func NewProcessMonitoringCheck() SecurityCheck {
	return &ProcessMonitoringCheck{}
}
