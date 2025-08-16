package storage

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/oarkflow/squealx"

	"github.com/oarkflow/auth/pkg/models"
)

// DatabaseType represents the type of database
type DatabaseType string

const (
	MySQL      DatabaseType = "mysql"
	PostgreSQL DatabaseType = "postgres"
	SQLite     DatabaseType = "sqlite"
)

// DatabaseStorage struct with database type awareness
type DatabaseStorage struct {
	db     *squealx.DB
	dbType DatabaseType
}

// NewDatabaseStorage creates a new database storage instance
func NewDatabaseStorage(db *squealx.DB) (*DatabaseStorage, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is nil")
	}
	fmt.Println(db.DriverName())
	storage := &DatabaseStorage{
		db:     db,
		dbType: DatabaseType(db.DriverName()),
	}

	// Create tables with database-specific schema
	if err := storage.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create database schema: %w", err)
	}

	return storage, nil
}

// createTables creates database tables with appropriate schema for each database type
func (d *DatabaseStorage) createTables() error {
	var queries []string

	switch d.dbType {
	case MySQL:
		queries = d.getMySQLSchema()
	case PostgreSQL:
		queries = d.getPostgreSQLSchema()
	case SQLite:
		queries = d.getSQLiteSchema()
	default:
		return fmt.Errorf("unsupported database type: %s", d.dbType)
	}

	for _, query := range queries {
		if _, err := d.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute schema query: %w", err)
		}
	}

	return nil
}

// getMySQLSchema returns MySQL-specific schema
func (d *DatabaseStorage) getMySQLSchema() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS users (
			pub_hex VARCHAR(255) PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			user_id BIGINT NOT NULL,
			login_type ENUM('simple', 'secured') DEFAULT 'simple',
			mfa_enabled BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			is_active BOOLEAN DEFAULT TRUE,
			failed_attempts INT DEFAULT 0,
			locked_until TIMESTAMP NULL,
			INDEX idx_users_username (username),
			INDEX idx_users_created_at (created_at),
			INDEX idx_users_login_type (login_type),
			INDEX idx_users_is_active (is_active)
		) ENGINE=InnoDB`,

		`CREATE TABLE IF NOT EXISTS credentials (
			user_id BIGINT NOT NULL,
			secret TEXT NOT NULL,
			metadata TEXT,
			secret_type VARCHAR(50) DEFAULT 'password' NOT NULL,
			integration_type VARCHAR(100),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, secret_type),
			INDEX idx_credentials_user_id (user_id),
			INDEX idx_credentials_secret_type (secret_type)
		) ENGINE=InnoDB`,

		`CREATE TABLE IF NOT EXISTS verification_tokens (
			id BIGINT PRIMARY KEY AUTO_INCREMENT,
			username VARCHAR(255) NOT NULL,
			token VARCHAR(255) NOT NULL,
			expires_at BIGINT NOT NULL,
			used BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_verification_tokens_username (username),
			INDEX idx_verification_tokens_token (token)
		) ENGINE=InnoDB`,

		`CREATE TABLE IF NOT EXISTS pending_registrations (
			id BIGINT PRIMARY KEY AUTO_INCREMENT,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			login_type ENUM('simple', 'secured') DEFAULT 'simple',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_pending_registrations_username (username)
		) ENGINE=InnoDB`,

		`CREATE TABLE IF NOT EXISTS audit_logs (
			id BIGINT PRIMARY KEY AUTO_INCREMENT,
			user_id VARCHAR(255),
			action VARCHAR(100) NOT NULL,
			resource VARCHAR(255),
			ip_address VARCHAR(45),
			user_agent TEXT,
			success BOOLEAN,
			error_message TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_audit_logs_user_id (user_id),
			INDEX idx_audit_logs_action (action),
			INDEX idx_audit_logs_created_at (created_at)
		) ENGINE=InnoDB`,
	}
}

// getPostgreSQLSchema returns PostgreSQL-specific schema
func (d *DatabaseStorage) getPostgreSQLSchema() []string {
	return []string{
		`CREATE TYPE login_type_enum AS ENUM ('simple', 'secured')`,

		`CREATE TABLE IF NOT EXISTS users (
			pub_hex VARCHAR(255) PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			user_id BIGINT NOT NULL,
			login_type login_type_enum DEFAULT 'simple',
			mfa_enabled BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			is_active BOOLEAN DEFAULT TRUE,
			failed_attempts INTEGER DEFAULT 0,
			locked_until TIMESTAMP NULL
		)`,

		`CREATE TABLE IF NOT EXISTS credentials (
			user_id BIGINT NOT NULL,
			secret TEXT NOT NULL,
			metadata TEXT,
			secret_type VARCHAR(50) DEFAULT 'password' NOT NULL,
			integration_type VARCHAR(100),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, secret_type)
		)`,

		`CREATE TABLE IF NOT EXISTS verification_tokens (
			id BIGSERIAL PRIMARY KEY,
			username VARCHAR(255) NOT NULL,
			token VARCHAR(255) NOT NULL,
			expires_at BIGINT NOT NULL,
			used BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS pending_registrations (
			id BIGSERIAL PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			login_type login_type_enum DEFAULT 'simple',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS audit_logs (
			id BIGSERIAL PRIMARY KEY,
			user_id VARCHAR(255),
			action VARCHAR(100) NOT NULL,
			resource VARCHAR(255),
			ip_address INET,
			user_agent TEXT,
			success BOOLEAN,
			error_message TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,

		// Indexes
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_users_login_type ON users(login_type)`,
		`CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_secret_type ON credentials(secret_type)`,
		`CREATE INDEX IF NOT EXISTS idx_verification_tokens_username ON verification_tokens(username)`,
		`CREATE INDEX IF NOT EXISTS idx_verification_tokens_token ON verification_tokens(token)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_registrations_username ON pending_registrations(username)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)`,
	}
}

// getSQLiteSchema returns SQLite-specific schema (original)
func (d *DatabaseStorage) getSQLiteSchema() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS users (
			pub_hex TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			user_id INTEGER NOT NULL,
			login_type TEXT DEFAULT 'simple' CHECK (login_type IN ('simple', 'secured')),
			mfa_enabled BOOLEAN DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			is_active BOOLEAN DEFAULT 1,
			failed_attempts INTEGER DEFAULT 0,
			locked_until DATETIME NULL
		)`,

		`CREATE TABLE IF NOT EXISTS credentials (
			user_id INTEGER NOT NULL,
			secret TEXT NOT NULL,
			metadata TEXT,
			secret_type TEXT DEFAULT 'password' NOT NULL,
			integration_type TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, secret_type)
		)`,

		`CREATE TABLE IF NOT EXISTS verification_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			token TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			used BOOLEAN DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS pending_registrations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			login_type TEXT DEFAULT 'simple' CHECK (login_type IN ('simple', 'secured')),
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id TEXT,
			action TEXT NOT NULL,
			resource TEXT,
			ip_address TEXT,
			user_agent TEXT,
			success BOOLEAN,
			error_message TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Indexes
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_users_login_type ON users(login_type)`,
		`CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_secret_type ON credentials(secret_type)`,
		`CREATE INDEX IF NOT EXISTS idx_verification_tokens_username ON verification_tokens(username)`,
		`CREATE INDEX IF NOT EXISTS idx_verification_tokens_token ON verification_tokens(token)`,
		`CREATE INDEX IF NOT EXISTS idx_pending_registrations_username ON pending_registrations(username)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)`,
	}
}

// upsertUser performs database-agnostic upsert operation for users
func (d *DatabaseStorage) upsertUser(pubHex string, info models.UserInfo) error {
	// First, try to update existing record
	result, err := d.db.Exec(`
		UPDATE users
		SET username = ?, user_id = ?, login_type = ?, mfa_enabled = ?, updated_at = CURRENT_TIMESTAMP
		WHERE pub_hex = ?`,
		info.Username, info.UserID, info.LoginType, info.MFAEnabled, pubHex)

	if err != nil {
		return err
	}

	// Check if any rows were affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	// If no rows were updated, insert new record
	if rowsAffected == 0 {
		_, err = d.db.Exec(`
			INSERT INTO users (pub_hex, username, user_id, login_type, mfa_enabled)
			VALUES (?, ?, ?, ?, ?)`,
			pubHex, info.Username, info.UserID, info.LoginType, info.MFAEnabled)
		return err
	}

	return nil
}

// upsertCredential performs database-agnostic upsert operation for credentials
func (d *DatabaseStorage) upsertCredential(userID int64, secret, secretType, metadata string) error {
	// First, try to update existing record
	result, err := d.db.Exec(`
		UPDATE credentials
		SET secret = ?, metadata = ?, updated_at = CURRENT_TIMESTAMP
		WHERE user_id = ? AND secret_type = ?`,
		secret, metadata, userID, secretType)

	if err != nil {
		return err
	}

	// Check if any rows were affected
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	// If no rows were updated, insert new record
	if rowsAffected == 0 {
		_, err = d.db.Exec(`
			INSERT INTO credentials (user_id, secret, secret_type, metadata)
			VALUES (?, ?, ?, ?)`,
			userID, secret, secretType, metadata)
		return err
	}

	return nil
}

// --- Verification Token Methods ---
func (d *DatabaseStorage) SetVerificationToken(username, token string, expiresAt int64) error {
	_, err := d.db.Exec(`INSERT INTO verification_tokens (username, token, expires_at, used) VALUES (?, ?, ?, ?)`,
		username, token, expiresAt, false)
	return err
}

func (d *DatabaseStorage) VerifyToken(username, token string) (bool, error) {
	var used bool
	var expiresAt int64
	err := d.db.QueryRow(`SELECT used, expires_at FROM verification_tokens WHERE username = ? AND token = ?`,
		username, token).Scan(&used, &expiresAt)
	if err != nil {
		return false, err
	}

	if used || expiresAt < time.Now().Unix() {
		return false, nil
	}

	_, err = d.db.Exec(`UPDATE verification_tokens SET used = ? WHERE username = ? AND token = ?`,
		true, username, token)
	return err == nil, err
}

// --- Pending Registration Methods ---
func (d *DatabaseStorage) CreatePendingRegistration(username, passwordHash, loginType string) error {
	_, err := d.db.Exec(`INSERT INTO pending_registrations (username, password_hash, login_type) VALUES (?, ?, ?)`,
		username, passwordHash, loginType)
	return err
}

func (d *DatabaseStorage) GetPendingRegistration(username string) (string, string, error) {
	var passwordHash, loginType string
	err := d.db.QueryRow(`SELECT password_hash, login_type FROM pending_registrations WHERE username = ?`,
		username).Scan(&passwordHash, &loginType)
	if err != nil {
		return "", "", err
	}
	return passwordHash, loginType, nil
}

func (d *DatabaseStorage) DeletePendingRegistration(username string) error {
	_, err := d.db.Exec(`DELETE FROM pending_registrations WHERE username = ?`, username)
	return err
}

// --- User Info and Credentials ---
func (d *DatabaseStorage) SetUserInfo(pubHex string, info models.UserInfo) error {
	return d.upsertUser(pubHex, info)
}

func (d *DatabaseStorage) GetUserInfo(pubHex string) (models.UserInfo, error) {
	var info models.UserInfo
	err := d.db.QueryRow(`SELECT user_id, username, login_type, mfa_enabled FROM users WHERE pub_hex = ?`,
		pubHex).Scan(&info.UserID, &info.Username, &info.LoginType, &info.MFAEnabled)
	if err != nil {
		return models.UserInfo{}, err
	}
	return info, nil
}

func (d *DatabaseStorage) GetUserInfoByUsername(username string) (models.UserInfo, error) {
	var info models.UserInfo
	err := d.db.QueryRow(`SELECT user_id, username, login_type, mfa_enabled FROM users WHERE username = ?`,
		username).Scan(&info.UserID, &info.Username, &info.LoginType, &info.MFAEnabled)
	if err != nil {
		return models.UserInfo{}, err
	}
	return info, nil
}

func (d *DatabaseStorage) SetUserSecret(userID int64, secret string) error {
	return d.upsertCredential(userID, secret, "password", "")
}

func (d *DatabaseStorage) GetUserSecret(userID int64) (string, error) {
	var secret string
	err := d.db.Get(&secret, `SELECT secret FROM credentials WHERE user_id = ? AND secret_type = 'password'`, userID)
	if err != nil {
		return "", err
	}
	return secret, nil
}

func (d *DatabaseStorage) SetUserPublicKey(userID int64, pubKeyX, pubKeyY string) error {
	pubKeyJSON, _ := json.Marshal(map[string]string{
		"PubKeyX": pubKeyX,
		"PubKeyY": pubKeyY,
	})
	return d.upsertCredential(userID, string(pubKeyJSON), "public_key", "")
}

func (d *DatabaseStorage) GetUserPublicKey(userID int64) (map[string]string, error) {
	var secret string
	err := d.db.Get(&secret, `SELECT secret FROM credentials WHERE user_id = ? AND secret_type = 'public_key'`, userID)
	if err != nil {
		return nil, err
	}

	var pubKey map[string]string
	if err := json.Unmarshal([]byte(secret), &pubKey); err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (d *DatabaseStorage) SetUserMFA(userID int64, secret string, backupCodes []string) error {
	backupCodesJSON, _ := json.Marshal(backupCodes)
	return d.upsertCredential(userID, secret, "mfa", string(backupCodesJSON))
}

func (d *DatabaseStorage) GetUserMFA(userID int64) (string, []string, error) {
	var secret, metadata string
	err := d.db.QueryRow(`SELECT secret, COALESCE(metadata, '') FROM credentials WHERE user_id = ? AND secret_type = 'mfa'`,
		userID).Scan(&secret, &metadata)
	if err != nil {
		return "", nil, err
	}

	var backupCodes []string
	if metadata != "" {
		json.Unmarshal([]byte(metadata), &backupCodes)
	}
	return secret, backupCodes, nil
}

func (d *DatabaseStorage) EnableMFA(userID int64) error {
	_, err := d.db.Exec(`UPDATE users SET mfa_enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?`,
		true, userID)
	return err
}

func (d *DatabaseStorage) DisableMFA(userID int64) error {
	_, err := d.db.Exec(`UPDATE users SET mfa_enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?`,
		false, userID)
	return err
}

func (d *DatabaseStorage) IsUserMFAEnabled(userID int64) (bool, error) {
	var mfaEnabled bool
	err := d.db.QueryRow(`SELECT mfa_enabled FROM users WHERE user_id = ?`, userID).Scan(&mfaEnabled)
	if err != nil {
		return false, err
	}
	return mfaEnabled, nil
}

func (d *DatabaseStorage) ValidateBackupCode(userID int64, code string) error {
	secret, backupCodes, err := d.GetUserMFA(userID)
	if err != nil {
		return err
	}

	// Check if code exists in backup codes
	found := false
	var newBackupCodes []string
	for _, backupCode := range backupCodes {
		if backupCode == code {
			found = true
		} else {
			newBackupCodes = append(newBackupCodes, backupCode)
		}
	}

	if !found {
		return fmt.Errorf("invalid backup code")
	}

	// Update backup codes without the used one
	return d.SetUserMFA(userID, secret, newBackupCodes)
}

func (d *DatabaseStorage) InvalidateBackupCode(userID int64, code string) error {
	return d.ValidateBackupCode(userID, code) // Same logic
}

// Helper function to detect database type from connection string or driver
func DetectDatabaseType(driverName string, dataSource string) DatabaseType {
	driverName = strings.ToLower(driverName)
	dataSource = strings.ToLower(dataSource)

	switch {
	case strings.Contains(driverName, "mysql") || strings.Contains(dataSource, "mysql"):
		return MySQL
	case strings.Contains(driverName, "postgres") || strings.Contains(driverName, "pgx") ||
		strings.Contains(dataSource, "postgres") || strings.Contains(dataSource, "postgresql"):
		return PostgreSQL
	case strings.Contains(driverName, "sqlite") || strings.Contains(dataSource, ".db") ||
		strings.Contains(dataSource, "sqlite"):
		return SQLite
	default:
		return SQLite // Default to SQLite
	}
}
