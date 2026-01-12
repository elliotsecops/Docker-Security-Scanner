package checks

import (
	"context"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
)

// MockDockerClient implements DockerClient interface for testing
type MockDockerClient struct {
	InspectFunc func(ctx context.Context, containerID string) (types.ContainerJSON, error)
	ListFunc    func(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error)
}

func (m *MockDockerClient) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	if m.InspectFunc != nil {
		return m.InspectFunc(ctx, containerID)
	}
	return types.ContainerJSON{}, nil
}

func (m *MockDockerClient) ContainerList(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error) {
	if m.ListFunc != nil {
		return m.ListFunc(ctx, options)
	}
	return nil, nil
}

func TestRootUserCheck(t *testing.T) {
	check := NewRootUserCheck()

	tests := []struct {
		name           string
		user           string
		expectedPassed bool
	}{
		{
			name:           "Root user string",
			user:           "root",
			expectedPassed: false,
		},
		{
			name:           "Root user ID 0",
			user:           "0",
			expectedPassed: false,
		},
		{
			name:           "Empty user (defaults to root)",
			user:           "",
			expectedPassed: false,
		},
		{
			name:           "Non-root user",
			user:           "appuser",
			expectedPassed: true,
		},
		{
			name:           "Non-root user ID 1000",
			user:           "1000",
			expectedPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockDockerClient{
				InspectFunc: func(ctx context.Context, containerID string) (types.ContainerJSON, error) {
					return types.ContainerJSON{
						Config: &container.Config{
							User: tt.user,
						},
					}, nil
				},
			}

			targetContainer := &types.Container{ID: "test-container"}
			result, err := check.Execute(context.Background(), targetContainer, mockClient)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Passed != tt.expectedPassed {
				t.Errorf("Expected passed=%v, got %v", tt.expectedPassed, result.Passed)
			}
		})
	}
}

func TestVulnerabilityCheck(t *testing.T) {
	check := NewVulnerabilityCheckWithConfig(nil)

	tests := []struct {
		name           string
		image          string
		expectedPassed bool
	}{
		{
			name:           "Vulnerable Ubuntu 14.04",
			image:          "ubuntu:14.04",
			expectedPassed: false,
		},
		{
			name:           "Vulnerable Alpine 3.6",
			image:          "alpine:3.6",
			expectedPassed: false,
		},
		{
			name:           "Safe Image",
			image:          "alpine:latest",
			expectedPassed: true,
		},
		{
			name:           "Custom Image",
			image:          "my-app:1.0.0",
			expectedPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockDockerClient{}
			targetContainer := &types.Container{
				ID:    "test-container",
				Image: tt.image,
			}

			result, err := check.Execute(context.Background(), targetContainer, mockClient)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Passed != tt.expectedPassed {
				t.Errorf("Expected passed=%v, got %v", tt.expectedPassed, result.Passed)
			}
		})
	}
}

func TestSecretsCheck(t *testing.T) {
	check := NewSecretsCheck()

	tests := []struct {
		name           string
		env            []string
		expectedPassed bool
	}{
		{
			name:           "Safe Env Vars",
			env:            []string{"PATH=/bin", "HOST=localhost"},
			expectedPassed: true,
		},
		{
			name:           "AWS Secret Key",
			env:            []string{"AWS_SECRET_ACCESS_KEY=12345"},
			expectedPassed: false,
		},
		{
			name:           "Generic Password",
			env:            []string{"DB_PASSWORD=secret"},
			expectedPassed: false,
		},
		{
			name:           "API Key",
			env:            []string{"API_KEY=abcdef"},
			expectedPassed: false,
		},
		{
			name:           "Empty Value Secret (might be ignored)",
			env:            []string{"PASSWORD="},
			expectedPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockDockerClient{
				InspectFunc: func(ctx context.Context, containerID string) (types.ContainerJSON, error) {
					return types.ContainerJSON{
						Config: &container.Config{
							Env: tt.env,
						},
					}, nil
				},
			}

			targetContainer := &types.Container{ID: "test-container"}
			result, err := check.Execute(context.Background(), targetContainer, mockClient)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Passed != tt.expectedPassed {
				t.Errorf("Expected passed=%v, got %v", tt.expectedPassed, result.Passed)
			}
		})
	}
}

func TestNetworkPolicyCheck(t *testing.T) {
	check := NewNetworkPolicyCheck()

	tests := []struct {
		name           string
		networkMode    container.NetworkMode
		privileged     bool
		expectedPassed bool
	}{
		{
			name:           "Host Network",
			networkMode:    "host",
			privileged:     false,
			expectedPassed: false,
		},
		{
			name:           "Privileged Mode",
			networkMode:    "bridge",
			privileged:     true,
			expectedPassed: false,
		},
		{
			name:           "Safe Config",
			networkMode:    "bridge",
			privileged:     false,
			expectedPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockDockerClient{
				InspectFunc: func(ctx context.Context, containerID string) (types.ContainerJSON, error) {
					return types.ContainerJSON{
						ContainerJSONBase: &types.ContainerJSONBase{
							HostConfig: &container.HostConfig{
								NetworkMode: tt.networkMode,
								Privileged:  tt.privileged,
							},
						},
					}, nil
				},
			}

			targetContainer := &types.Container{ID: "test-container"}
			result, err := check.Execute(context.Background(), targetContainer, mockClient)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Passed != tt.expectedPassed {
				t.Errorf("Expected passed=%v, got %v", tt.expectedPassed, result.Passed)
			}
		})
	}
}

func TestImageIntegrityCheck(t *testing.T) {
	check := NewImageIntegrityCheck()

	tests := []struct {
		name           string
		image          string
		expectedPassed bool
	}{
		{
			name:           "Latest Tag",
			image:          "nginx:latest",
			expectedPassed: false,
		},
		{
			name:           "Untrusted Registry",
			image:          "evil.com/app:1.0",
			expectedPassed: false,
		},
		{
			name:           "Docker Hub Official",
			image:          "nginx:1.19",
			expectedPassed: true,
		},
		{
			name:           "GCR Trusted",
			image:          "gcr.io/my-project/app:v1",
			expectedPassed: true,
		},
		{
			name:           "Library Prefix",
			image:          "library/postgres:13",
			expectedPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockDockerClient{}
			targetContainer := &types.Container{
				ID:    "test-container",
				Image: tt.image,
			}

			result, err := check.Execute(context.Background(), targetContainer, mockClient)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Passed != tt.expectedPassed {
				t.Errorf("Expected passed=%v, got %v", tt.expectedPassed, result.Passed)
			}
		})
	}
}

func TestResourceLimitsCheck(t *testing.T) {
	check := NewResourceLimitsCheck()
	
	val2048 := int64(2048)

	tests := []struct {
		name           string
		hostConfig     *container.HostConfig
		expectedPassed bool
	}{
		{
			name: "No Limits",
			hostConfig: &container.HostConfig{
				Resources: container.Resources{
					Memory:    0,
					NanoCPUs:  0,
					PidsLimit: nil,
				},
			},
			expectedPassed: false,
		},
		{
			name: "Memory Limit Only",
			hostConfig: &container.HostConfig{
				Resources: container.Resources{
					Memory:    1024 * 1024,
					NanoCPUs:  0,
					PidsLimit: nil,
				},
			},
			expectedPassed: false,
		},
		{
			name: "All Limits Set",
			hostConfig: &container.HostConfig{
				Resources: container.Resources{
					Memory:    1024 * 1024,
					NanoCPUs:  1000000000,
					PidsLimit: &val2048,
				},
			},
			expectedPassed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockDockerClient{
				InspectFunc: func(ctx context.Context, containerID string) (types.ContainerJSON, error) {
					return types.ContainerJSON{
						ContainerJSONBase: &types.ContainerJSONBase{
							HostConfig: tt.hostConfig,
						},
					}, nil
				},
			}

			targetContainer := &types.Container{ID: "test-container"}
			result, err := check.Execute(context.Background(), targetContainer, mockClient)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Passed != tt.expectedPassed {
				t.Errorf("Expected passed=%v, got %v", tt.expectedPassed, result.Passed)
			}
		})
	}
}

func TestExposedPortsCheck(t *testing.T) {
	check := NewExposedPortsCheck()

	tests := []struct {
		name           string
		exposedPorts   nat.PortSet
		portBindings   nat.PortMap
		expectedPassed bool
	}{
		{
			name: "No Exposed or Bound Ports",
			exposedPorts: nat.PortSet{},
			portBindings: nat.PortMap{},
			expectedPassed: true,
		},
		{
			name: "Exposed But Not Bound (Safe-ish)",
			exposedPorts: nat.PortSet{
				"80/tcp": {},
			},
			portBindings: nat.PortMap{},
			expectedPassed: true,
		},
		{
			name: "Bound Ports (Warning)",
			exposedPorts: nat.PortSet{
				"80/tcp": {},
			},
			portBindings: nat.PortMap{
				"80/tcp": {{HostPort: "8080"}},
			},
			expectedPassed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockDockerClient{
				InspectFunc: func(ctx context.Context, containerID string) (types.ContainerJSON, error) {
					return types.ContainerJSON{
						Config: &container.Config{
							ExposedPorts: tt.exposedPorts,
						},
						ContainerJSONBase: &types.ContainerJSONBase{
							HostConfig: &container.HostConfig{
								PortBindings: tt.portBindings,
							},
						},
					}, nil
				},
			}

			targetContainer := &types.Container{ID: "test-container"}
			result, err := check.Execute(context.Background(), targetContainer, mockClient)

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Passed != tt.expectedPassed {
				t.Errorf("Expected passed=%v, got %v", tt.expectedPassed, result.Passed)
			}
		})
	}
}