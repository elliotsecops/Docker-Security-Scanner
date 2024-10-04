### Escáner de Seguridad de Docker

#### Descripción General

Este proyecto es un escáner de seguridad de Docker minimalista pero potente implementado en Go. El escáner verifica los contenedores en ejecución en busca de problemas de seguridad comunes, como ejecutarse como root, puertos expuestos y actualizaciones de seguridad faltantes. El script utiliza el SDK de Docker para Go para interactuar con Docker.

#### Características

- **Verificación de Ejecución como Root:** Identifica contenedores que se ejecutan como el usuario root.
- **Verificación de Puertos Expuestos:** Detecta puertos expuestos en contenedores en ejecución.
- **Actualizaciones de Seguridad Faltantes (Simplificado):** Una verificación simplificada de actualizaciones de seguridad faltantes.

#### Requisitos Previos

- **Go (Golang):** Asegúrate de tener Go instalado en tu sistema. Puedes descargarlo desde [golang.org](https://golang.org/dl/).
- **Docker:** Asegúrate de tener Docker instalado y en ejecución en tu sistema. Puedes descargarlo desde [docker.com](https://www.docker.com/products/docker-desktop).

#### Estructura del Proyecto

```
docker-security-scanner/
├── Dockerfile
├── README.md
├── .gitignore
└── main.go
```

#### Instrucciones de Configuración

1. **Clonar el Repositorio:**
   ```bash
   git clone https://github.com/elliotsecops/docker-security-scanner.git
   cd docker-security-scanner
   ```

2. **Construir el Escáner de Seguridad de Docker:**
   ```bash
   go build -o docker-security-scanner
   ```

#### Instrucciones de Uso

##### Ejecutar el Escáner de Seguridad de Docker

1. **Asegúrate de que Docker esté en Ejecución:**
   - Asegúrate de que Docker esté en ejecución en tu sistema. Puedes verificarlo ejecutando:
     ```bash
     docker ps
     ```

2. **Ejecutar el Escáner de Seguridad de Docker:**
   ```bash
   ./docker-security-scanner
   ```

##### Ejemplo de Salida

Cuando ejecutes el escáner, mostrará los resultados de las verificaciones de seguridad para cada contenedor en ejecución. Aquí tienes un ejemplo de cómo podría verse la salida:

```
Listando contenedores...
Conectando al socket Unix...
Encontrados 1 contenedores
Inspeccionando contenedor <container_id>...
El contenedor <container_id> se está ejecutando como root
El contenedor <container_id> tiene el puerto expuesto: 80/tcp -> 8080
```

#### Verificaciones de Seguridad Realizadas

##### Ejecución como Root

El escáner verifica si un contenedor se está ejecutando como el usuario root inspeccionando la sección `Config` de la respuesta JSON del contenedor. Si el contenedor se está ejecutando como root, mostrará:

```
El contenedor <container_id> se está ejecutando como root
```

##### Puertos Expuestos

El escáner verifica los puertos expuestos examinando la sección `HostConfig` de la respuesta JSON del contenedor. Si el contenedor tiene puertos expuestos, mostrará:

```
El contenedor <container_id> tiene el puerto expuesto: <port> -> <host_port>
```

##### Actualizaciones de Seguridad Faltantes (Simplificado)

Esta verificación es más compleja y generalmente implica inspeccionar el sistema de archivos del contenedor o usar herramientas de gestión de paquetes para verificar paquetes desactualizados. La implementación actual es simplificada y no realiza una verificación detallada.

#### Personalizar el Escáner

Puedes personalizar el escáner para incluir más verificaciones de seguridad o modificar las existentes. Aquí tienes algunas ideas:

1. **Verificación de Archivos Sensibles:**
   - Añade una verificación para inspeccionar el sistema de archivos del contenedor en busca de archivos sensibles (por ejemplo, `.env`, `config.json`).

2. **Verificación de Contraseñas Débiles:**
   - Añade una verificación para inspeccionar las cuentas de usuario del contenedor en busca de contraseñas débiles.

3. **Verificación de Servicios Innecesarios:**
   - Añade una verificación para inspeccionar los servicios en ejecución del contenedor en busca de servicios innecesarios o inseguros (por ejemplo, SSH).

#### Contribuir

¡Las contribuciones son bienvenidas! Si tienes ideas para nuevas verificaciones de seguridad o mejoras a las existentes, no dudes en enviar un pull request!

#### Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

---

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
