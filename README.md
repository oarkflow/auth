# Secure Authentication Service

A robust, production-ready authentication service built in Go that supports both simple username/password authentication and secured cryptographic proof-based authentication using ECDSA signatures and PASETO tokens.

## Features

### Authentication Methods
- **Simple Login**: Traditional username/password authentication with bcrypt hashing
- **Secured Login**: Cryptographic proof-based authentication using ECDSA signatures
- **Single Sign-On (SSO)**: Token-based SSO support
- **Password Reset**: Secure password reset with email/SMS verification

### Security Features
- **Rate Limiting**: Configurable request and login attempt limits
- **Session Management**: Secure session handling with token blacklisting
- **Audit Logging**: Comprehensive request and authentication logging
- **Security Headers**: Production-ready security headers (CSP, HSTS, etc.)
- **Input Validation**: SQL injection and XSS protection
- **Password Policy**: Configurable password strength requirements

### Production Ready
- **Environment Configuration**: Development and production configurations
- **Docker Support**: Containerization with health checks
- **Monitoring**: Health endpoints and metrics
- **Database**: SQLite with migration support
- **TLS Support**: HTTPS with configurable SSL settings

## Quick Start

### Prerequisites
- Go 1.21 or later
- SQLite3

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd auth
```

2. Install dependencies:
```bash
go mod tidy
```

3. Set up environment variables:
```bash
cp .env.development .env
# Edit .env with your configuration
```

4. Build and run:
```bash
go build -o auth-server .
./auth-server
```

The service will start on `http://localhost:8080`

## Configuration

### Environment Variables

#### Basic Configuration
- `ENVIRONMENT`: Deployment environment (development/production)
- `LISTEN_ADDR`: Server listen address (default: :8080)
- `JWT_SECRET`: Secret key for PASETO tokens (required in production)
- `DATABASE_URL`: SQLite database path (default: vault.db)

#### Security Settings
- `ENABLE_HTTPS`: Enable HTTPS (default: false)
- `ENABLE_SECURITY_HEADERS`: Enable security headers (default: true)
- `ENABLE_AUDIT_LOGGING`: Enable audit logging (default: false)
- `CORS_ORIGINS`: Allowed CORS origins (comma-separated)
- `TRUSTED_PROXIES`: Trusted proxy IP ranges (comma-separated)

#### Rate Limiting
- `RATE_LIMIT_REQUESTS`: Max requests per window (default: 30)
- `RATE_LIMIT_WINDOW`: Rate limit window duration (default: 1m)
- `MAX_LOGIN_ATTEMPTS`: Max failed login attempts (default: 5)

#### Password Policy
- `PASSWORD_MIN_LENGTH`: Minimum password length (default: 8)
- `PASSWORD_REQUIRE_UPPER`: Require uppercase letters (default: true)
- `PASSWORD_REQUIRE_LOWER`: Require lowercase letters (default: true)
- `PASSWORD_REQUIRE_DIGIT`: Require digits (default: true)
- `PASSWORD_REQUIRE_SPECIAL`: Require special characters (default: true)

## API Documentation

### Authentication Endpoints

#### Register User
```http
POST /register
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=SecurePass123!&loginType=simple
```

#### Simple Login
```http
POST /simple-login
Content-Type: application/x-www-form-urlencoded

username=user@example.com&password=SecurePass123!
```

#### Secured Login (Cryptographic Proof)
```http
POST /secured-login
Content-Type: multipart/form-data

keyfile=<key-file>&password=<password>
```

#### API Login
```http
POST /api/login
Content-Type: application/json

{
  "username": "user@example.com",
  "password": "SecurePass123!"
}
```

#### Logout
```http
POST /logout
```

### Utility Endpoints

#### Health Check
```http
GET /health
```

#### Get Nonce (for cryptographic proof)
```http
GET /nonce
```

#### User Information
```http
GET /api/userinfo
Authorization: Bearer <token>
```

### Password Reset

#### Request Reset
```http
POST /forgot-password
Content-Type: application/x-www-form-urlencoded

username=user@example.com
```

#### Reset Password
```http
POST /reset-password
Content-Type: application/x-www-form-urlencoded

token=<reset-token>&password=<new-password>&confirmPassword=<new-password>
```

## Authentication Flow

### Simple Authentication
1. User registers with username/password
2. Email/SMS verification (development: printed to console)
3. User can login with credentials
4. Server returns PASETO token in secure cookie

### Secured Authentication
1. User registers choosing "secured" login type
2. Email/SMS verification
3. Server generates ECDSA key pair
4. Private key encrypted with user password
5. Key file downloaded by user
6. Login requires key file + password
7. Client generates cryptographic proof
8. Server validates proof and issues token

## Security Considerations

### Production Deployment
- Set a strong `JWT_SECRET` (minimum 32 characters)
- Enable HTTPS with proper certificates
- Configure specific CORS origins (no wildcards)
- Use reverse proxy for SSL termination
- Enable audit logging
- Monitor failed login attempts
- Regular security audits

### Database Security
- SQLite file permissions set to 600
- Regular database backups
- Encrypted backups for sensitive data

### Network Security
- Firewall configuration
- Rate limiting at proxy level
- DDoS protection
- Regular security scanning

## Docker Deployment

### Build and run with Docker:
```bash
docker build -t auth-service .
docker run -d -p 8080:8080 --name auth-service auth-service
```

### Docker Compose (with SSL):
```bash
docker-compose up -d
```

## Monitoring and Logging

### Health Endpoints
- `GET /health`: Basic health check
- `GET /api/status`: Detailed status information

### Audit Logging
When enabled, logs include:
- Request details (method, path, IP, user agent)
- Response status and timing
- Authentication events
- Failed login attempts

### Metrics
- Request count and timing
- Authentication success/failure rates
- Active sessions
- Database performance

## Development

### Running Tests
```bash
go test ./...
```

### Building
```bash
go build -o auth-server .
```

### Development with Hot Reload
```bash
# Install air for hot reloading
go install github.com/cosmtrek/air@latest
air
```

## Troubleshooting

### Common Issues

#### "JWT_SECRET must be set in production"
Set the JWT_SECRET environment variable with a secure random string.

#### Database permission errors
Ensure the SQLite database file has proper permissions (600) and the directory is writable.

#### CORS errors
Configure CORS_ORIGINS with the specific domains that need access.

#### Rate limiting issues
Adjust RATE_LIMIT_REQUESTS and RATE_LIMIT_WINDOW for your use case.

### Logging
Check logs for detailed error information:
```bash
# View systemd logs (if using systemd)
journalctl -u auth-service -f

# View Docker logs
docker logs auth-service -f
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run security checks
6. Submit a pull request

## License

[Your License Here]

## Support

For questions and support:
- Email: [your.email@company.com]
- Documentation: [Documentation URL]
- Issues: [Issue Tracker URL]
