# Docker Security Scanner

A simplified Docker container security scanner that checks your running containers for common security issues.

## Features

- **Root User Detection** - Identifies containers running as root
- **Exposed Ports Check** - Analyzes port bindings and exposure
- **Vulnerability Scanning** - Basic image vulnerability detection
- **Secrets Detection** - Finds potential secrets in environment variables
- **Network Policy Check** - Verifies network and privileged settings
- **Resource Limits Check** - Ensures resource constraints are set
- **Image Integrity Check** - Validates image sources and tags
- **Process Monitoring** - Monitors container process status

## Quick Start

```bash
# Build the scanner
go build -o docker-scanner ./cmd/scanner

# Run with default configuration
./docker-scanner
```

## Configuration

Create a `config.yaml` file:

```yaml
scanner:
  max_concurrent_scans: 10
  timeout: "30m"
  scan_stopped_containers: false
  exclude_images: []
  exclude_names: []

docker:
  socket_path: "/var/run/docker.sock"
  api_version: "1.41"
  tls_verify: false

security_checks:
  root_user_check: true
  exposed_ports_check: true
  vulnerability_check: true
  secrets_check: true
  network_policy_check: true
  resource_limits_check: true
  image_integrity_check: true
  process_monitoring_check: true

reporting:
  output_dir: "./reports"
  formats: ["json"]
  include_details: true

logging:
  level: "info"
  format: "text"
  output: "stdout"
```

## Usage

```bash
# Run with custom config
./docker-scanner --config /path/to/config.yaml

# Run with environment variables
export DSS_DOCKER_SOCKET_PATH=/var/run/docker.sock
./docker-scanner
```

## Output

Reports are generated in JSON format in the configured output directory:

```json
{
  "scan_id": "scan-1234567890",
  "timestamp": "2024-01-10T12:00:00Z",
  "duration": "5s",
  "containers_scanned": 5,
  "total_issues": 12,
  "compliance_score": 75.0,
  "container_results": { ... }
}
```

## Requirements

- Go 1.23+
- Docker running with accessible socket
- Sufficient permissions to inspect containers

## License

MIT
