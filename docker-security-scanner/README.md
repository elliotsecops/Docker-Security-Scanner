Certainly! Below is a detailed README for your Docker security scanner project, focusing on how users can use the script to test the security of their containers.

### Docker Security Scanner

#### Overview

This project is a minimalist yet powerful Docker security scanner implemented in Go. The scanner checks running containers for common security issues such as running as root, exposed ports, and missing security updates. The script leverages the Docker SDK for Go to interact with Docker.

#### Features

- **Running as Root Check:** Identifies containers running as the root user.
- **Exposed Ports Check:** Detects exposed ports on running containers.
- **Missing Security Updates (Simplified):** A simplified check for missing security updates.

#### Prerequisites

- **Go (Golang):** Ensure Go is installed on your system. You can download it from [golang.org](https://golang.org/dl/).
- **Docker:** Ensure Docker is installed and running on your system. You can download it from [docker.com](https://www.docker.com/products/docker-desktop).

#### Project Structure

```
docker-security-scanner/
├── Dockerfile
├── README.md
├── .gitignore
└── main.go
```

#### Setup Instructions

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/elliotsecops/docker-security-scanner.git
   cd docker-security-scanner
   ```

2. **Build the Docker Security Scanner:**
   ```bash
   go build -o docker-security-scanner
   ```

#### Usage Instructions

##### Running the Docker Security Scanner

1. **Ensure Docker is Running:**
   - Make sure Docker is running on your system. You can verify this by running:
     ```bash
     docker ps
     ```

2. **Run the Docker Security Scanner:**
   ```bash
   ./docker-security-scanner
   ```

##### Example Output

When you run the scanner, it will output the results of the security checks for each running container. Here's an example of what the output might look like:

```
Listing containers...
Dialing Unix socket...
Found 1 containers
Inspecting container <container_id>...
Container <container_id> is running as root
Container <container_id> has exposed port: 80/tcp -> 8080
```

#### Security Checks Performed

##### Running as Root

The scanner checks if a container is running as the root user by inspecting the `Config` section of the container's JSON response. If the container is running as root, it will output:

```
Container <container_id> is running as root
```

##### Exposed Ports

The scanner checks for exposed ports by examining the `HostConfig` section of the container's JSON response. If the container has exposed ports, it will output:

```
Container <container_id> has exposed port: <port> -> <host_port>
```

##### Missing Security Updates (Simplified)

This check is more complex and typically involves inspecting the container's filesystem or using package management tools to check for outdated packages. The current implementation is simplified and does not perform a detailed check.

#### Customizing the Scanner

You can customize the scanner to include more security checks or modify the existing ones. Here are some ideas:

1. **Check for Sensitive Files:**
   - Add a check to inspect the container's filesystem for sensitive files (e.g., `.env`, `config.json`).

2. **Check for Weak Passwords:**
   - Add a check to inspect the container's user accounts for weak passwords.

3. **Check for Unnecessary Services:**
   - Add a check to inspect the container's running services for unnecessary or insecure services (e.g., SSH).

#### Contributing

Contributions are welcome! If you have ideas for new security checks or improvements to the existing ones, feel free to submit a pull request.

#### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
