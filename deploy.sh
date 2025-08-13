#!/bin/bash

# Production Deployment Script for Auth Service
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="auth-service"
VERSION=$(git describe --tags --always || echo "v1.0.0")
ENVIRONMENT=${1:-production}

echo -e "${GREEN}Starting deployment of ${APP_NAME} ${VERSION} to ${ENVIRONMENT}${NC}"

# Pre-deployment checks
echo -e "${YELLOW}Running pre-deployment checks...${NC}"

# Check if required environment variables are set
REQUIRED_VARS=(
    "JWT_SECRET"
)

for var in "${REQUIRED_VARS[@]}"; do
    if [[ -z "${!var:-}" ]]; then
        echo -e "${RED}Error: Required environment variable $var is not set${NC}"
        exit 1
    fi
done

# Validate JWT secret strength
if [[ ${#JWT_SECRET} -lt 32 ]]; then
    echo -e "${RED}Error: JWT_SECRET must be at least 32 characters long${NC}"
    exit 1
fi

echo -e "${GREEN}Pre-deployment checks passed${NC}"

# Build and test
echo -e "${YELLOW}Building application...${NC}"
go mod tidy
go test ./...
go build -o ${APP_NAME} .

echo -e "${GREEN}Build completed successfully${NC}"

# Database migration/setup
echo -e "${YELLOW}Setting up database...${NC}"
mkdir -p /var/lib/github.com/oarkflow/auth
chmod 750 /var/lib/github.com/oarkflow/auth

# Security checks
echo -e "${YELLOW}Running security checks...${NC}"

# Check file permissions
find . -name "*.go" -exec chmod 644 {} \;
find . -name "*.html" -exec chmod 644 {} \;
chmod 755 ${APP_NAME}

# Generate TLS certificates if needed
if [[ "${ENABLE_HTTPS:-false}" == "true" ]]; then
    if [[ ! -f "server.crt" || ! -f "server.key" ]]; then
        echo -e "${YELLOW}Generating self-signed certificate for HTTPS...${NC}"
        openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=localhost"
        chmod 600 server.key
        chmod 644 server.crt
        echo -e "${YELLOW}Note: Replace with proper certificates in production${NC}"
    fi
fi

# Start the service
echo -e "${YELLOW}Starting ${APP_NAME}...${NC}"

# Create systemd service if doesn't exist
if [[ ! -f "/etc/systemd/system/${APP_NAME}.service" ]]; then
    cat > "/etc/systemd/system/${APP_NAME}.service" << EOF
[Unit]
Description=${APP_NAME}
After=network.target

[Service]
Type=simple
User=auth
Group=auth
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/${APP_NAME}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${APP_NAME}

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/auth

# Environment
EnvironmentFile=/etc/${APP_NAME}/${APP_NAME}.env

[Install]
WantedBy=multi-user.target
EOF

    # Create environment file directory
    mkdir -p "/etc/${APP_NAME}"

    # Copy environment file
    if [[ -f ".env.${ENVIRONMENT}" ]]; then
        cp ".env.${ENVIRONMENT}" "/etc/${APP_NAME}/${APP_NAME}.env"
        chmod 600 "/etc/${APP_NAME}/${APP_NAME}.env"
    fi

    systemctl daemon-reload
    systemctl enable ${APP_NAME}
fi

# Start/restart service
systemctl restart ${APP_NAME}

# Health check
echo -e "${YELLOW}Performing health check...${NC}"
sleep 5

for i in {1..10}; do
    if curl -f http://localhost:8080/health > /dev/null 2>&1; then
        echo -e "${GREEN}Health check passed!${NC}"
        break
    fi
    if [[ $i -eq 10 ]]; then
        echo -e "${RED}Health check failed after 10 attempts${NC}"
        systemctl status ${APP_NAME}
        exit 1
    fi
    sleep 2
done

echo -e "${GREEN}Deployment completed successfully!${NC}"
echo -e "${GREEN}Service is running at: http://localhost:8080${NC}"

# Show service status
systemctl status ${APP_NAME} --no-pager
