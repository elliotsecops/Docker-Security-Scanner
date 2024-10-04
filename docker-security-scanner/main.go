package main

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "net/http"
    "sync"
)

func main() {
    client := newUnixSocketClient()
    containers, err := listContainers(client)
    if err != nil {
        fmt.Printf("Failed to list containers: %v\n", err)
        return
    }

    var wg sync.WaitGroup
    for _, container := range containers {
        wg.Add(1)
        go func(container Container) { // Pass container as an argument
            defer wg.Done()
            checkContainerSecurity(client, container.ID)
        }(container) // Pass container to the goroutine
    }
    wg.Wait()
}

func newUnixSocketClient() *http.Client {
    return &http.Client{
        Transport: &http.Transport{
            DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
                fmt.Println("Dialing Unix socket...")
                return net.Dial("unix", "/var/run/docker.sock")
            },
        },
    }
}

type Container struct {
    ID     string `json:"Id"`
    Names  []string `json:"Names"`
    Image  string `json:"Image"`
    State  string `json:"State"`
    Status string `json:"Status"`
}

func listContainers(client *http.Client) ([]Container, error) {
    fmt.Println("Listing containers...")
    resp, err := client.Get("http://docker/containers/json?all=1")
    if err != nil {
        return nil, fmt.Errorf("failed to get containers list: %w", err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    var containers []Container
    err = json.Unmarshal(body, &containers)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
    }

    fmt.Printf("Found %d containers\n", len(containers))
    return containers, nil
}

type ContainerDetails struct {
    Config struct {
        User string `json:"User"`
    } `json:"Config"`
    HostConfig struct {
        PortBindings map[string][]struct {
            HostPort string `json:"HostPort"`
        } `json:"PortBindings"`
    } `json:"HostConfig"`
}

func inspectContainer(client *http.Client, containerID string) (*ContainerDetails, error) {
    fmt.Printf("Inspecting container %s...\n", containerID)
    resp, err := client.Get(fmt.Sprintf("http://docker/containers/%s/json", containerID))
    if err != nil {
        return nil, fmt.Errorf("failed to inspect container %s: %w", containerID, err)
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read response body: %w", err)
    }

    var details ContainerDetails
    err = json.Unmarshal(body, &details)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
    }

    return &details, nil
}

func checkContainerSecurity(client *http.Client, containerID string) {
    details, err := inspectContainer(client, containerID)
    if err != nil {
        fmt.Printf("Error inspecting container %s: %v\n", containerID, err)
        return
    }

    if details.Config.User == "" || details.Config.User == "0" {
        fmt.Printf("Container %s is running as root\n", containerID)
    }

    for port, bindings := range details.HostConfig.PortBindings {
        for _, binding := range bindings {
            if binding.HostPort != "" {
                fmt.Printf("Container %s has exposed port: %s -> %s\n", containerID, port, binding.HostPort)
            }
        }
    }
}