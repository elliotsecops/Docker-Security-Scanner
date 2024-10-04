# Use an outdated base image
FROM ubuntu:16.04

# Install outdated software
RUN apt-get update && apt-get install -y \
    nginx \
    curl \
    vim \
    openssh-server

# Expose a port
EXPOSE 80

# Run as root
USER root

# Create the /app directory
RUN mkdir -p /app

# Add sensitive files
RUN echo "SECRET_KEY=supersecret" > /app/.env

# Add a user with a weak password
RUN useradd -m -p $(openssl passwd -1 'weakpassword') testuser

# Start a vulnerable service
CMD ["nginx", "-g", "daemon off;"]