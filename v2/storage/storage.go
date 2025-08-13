package storage

import (
	"encoding/json"
	"fmt"

	"github.com/oarkflow/auth/v2/models"

	"github.com/oarkflow/squealx"
	"github.com/oarkflow/squealx/drivers/sqlite"
)

// --- Vault Storage Interface ---
type Storage interface {
	SetUserInfo(pubHex string, info models.UserInfo) error
	GetUserInfo(pubHex string) (models.UserInfo, error)
	GetUserInfoByUsername(username string) (models.UserInfo, error)
	SetUserSecret(userID, secret string) error
	GetUserSecret(userID string) (string, error)
	SetUserPublicKey(userID string, pubKeyX, pubKeyY string) error
	GetUserPublicKey(userID string) (map[string]string, error)
	SetUserMFA(userID string, secret string, backupCodes []string) error
	GetUserMFA(userID string) (string, []string, error)
	EnableMFA(userID string) error
	DisableMFA(userID string) error
	IsUserMFAEnabled(userID string) (bool, error)
	ValidateBackupCode(userID, code string) error
	InvalidateBackupCode(userID, code string) error
}

// --- SQLite Vault Storage ---
type DatabaseStorage struct {
	db *squealx.DB
}

func NewDatabaseStorage(dbPath string) (*DatabaseStorage, error) {
	db, err := sqlite.Open(dbPath, "sqlite")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create tables with improved schema and indexes
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		pub_hex TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		user_id TEXT NOT NULL,
		login_type TEXT DEFAULT 'simple' CHECK (login_type IN ('simple', 'secured')),
		mfa_enabled BOOLEAN DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		is_active BOOLEAN DEFAULT 1,
		failed_attempts INTEGER DEFAULT 0,
		locked_until DATETIME NULL
	);

	CREATE TABLE IF NOT EXISTS credentials (
		user_id TEXT NOT NULL,
		secret TEXT NOT NULL,
		metadata TEXT,
		secret_type TEXT DEFAULT 'password' NOT NULL,
		integration_type TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (user_id, secret_type)
	);

	-- Central Authentication System tables
	CREATE TABLE IF NOT EXISTS clients (
		client_id TEXT PRIMARY KEY,
		client_secret TEXT NOT NULL,
		name TEXT NOT NULL,
		redirect_uris TEXT NOT NULL, -- JSON array
		scopes TEXT NOT NULL, -- JSON array
		is_approved BOOLEAN DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS authorization_codes (
		code TEXT PRIMARY KEY,
		client_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		redirect_uri TEXT NOT NULL,
		scopes TEXT NOT NULL, -- JSON array
		expires_at DATETIME NOT NULL,
		used BOOLEAN DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (client_id) REFERENCES clients (client_id),
		FOREIGN KEY (user_id) REFERENCES users (user_id)
	);

	CREATE TABLE IF NOT EXISTS access_tokens (
		token TEXT PRIMARY KEY,
		client_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		scopes TEXT NOT NULL, -- JSON array
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (client_id) REFERENCES clients (client_id),
		FOREIGN KEY (user_id) REFERENCES users (user_id)
	);

	CREATE TABLE IF NOT EXISTS refresh_tokens (
		token TEXT PRIMARY KEY,
		client_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (client_id) REFERENCES clients (client_id),
		FOREIGN KEY (user_id) REFERENCES users (user_id)
	);

	-- Performance indexes
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
	CREATE INDEX IF NOT EXISTS idx_users_login_type ON users(login_type);
	CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
	CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
	CREATE INDEX IF NOT EXISTS idx_credentials_secret_type ON credentials(secret_type);
	CREATE INDEX IF NOT EXISTS idx_clients_created_at ON clients(created_at);
	CREATE INDEX IF NOT EXISTS idx_authorization_codes_client_id ON authorization_codes(client_id);
	CREATE INDEX IF NOT EXISTS idx_authorization_codes_user_id ON authorization_codes(user_id);
	CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at);
	CREATE INDEX IF NOT EXISTS idx_access_tokens_client_id ON access_tokens(client_id);
	CREATE INDEX IF NOT EXISTS idx_access_tokens_user_id ON access_tokens(user_id);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client_id ON refresh_tokens(client_id);

	-- Audit log table
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT,
		action TEXT NOT NULL,
		resource TEXT,
		ip_address TEXT,
		user_agent TEXT,
		success BOOLEAN,
		error_message TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to create database schema: %w", err)
	}

	return &DatabaseStorage{db: db}, nil
}

func (v *DatabaseStorage) SetUserInfo(pubHex string, info models.UserInfo) error {
	_, err := v.db.Exec(`INSERT OR REPLACE INTO users (pub_hex, username, user_id, login_type, mfa_enabled) VALUES (?, ?, ?, ?, ?)`,
		pubHex, info.Username, info.UserID, info.LoginType, info.MFAEnabled)
	return err
}

func (v *DatabaseStorage) GetUserInfo(pubHex string) (models.UserInfo, error) {
	var info models.UserInfo
	err := v.db.QueryRow(`SELECT user_id, username, login_type, mfa_enabled FROM users WHERE pub_hex = ?`, pubHex).Scan(
		&info.UserID, &info.Username, &info.LoginType, &info.MFAEnabled)
	if err != nil {
		return models.UserInfo{}, err
	}
	return info, nil
}

func (v *DatabaseStorage) GetUserInfoByUsername(username string) (models.UserInfo, error) {
	var info models.UserInfo
	err := v.db.QueryRow(`SELECT user_id, username, login_type, mfa_enabled FROM users WHERE username = ?`, username).Scan(
		&info.UserID, &info.Username, &info.LoginType, &info.MFAEnabled)
	if err != nil {
		return models.UserInfo{}, err
	}
	return info, nil
}

func (v *DatabaseStorage) SetUserSecret(userID, secret string) error {
	_, err := v.db.Exec(`INSERT OR REPLACE INTO credentials (user_id, secret, secret_type) VALUES (?, ?, 'password')`, userID, secret)
	return err
}

func (v *DatabaseStorage) GetUserSecret(userID string) (string, error) {
	var secret string
	err := v.db.Get(&secret, `SELECT secret FROM credentials WHERE user_id = ? AND secret_type = 'password'`, userID)
	if err != nil {
		return "", err
	}
	return secret, nil
}

// New methods for public key storage
func (v *DatabaseStorage) SetUserPublicKey(userID string, pubKeyX, pubKeyY string) error {
	pubKeyJSON, _ := json.Marshal(map[string]string{
		"PubKeyX": pubKeyX,
		"PubKeyY": pubKeyY,
	})
	_, err := v.db.Exec(`INSERT OR REPLACE INTO credentials (user_id, secret, secret_type) VALUES (?, ?, 'public_key')`, userID, string(pubKeyJSON))
	return err
}

func (v *DatabaseStorage) GetUserPublicKey(userID string) (map[string]string, error) {
	var secret string
	err := v.db.Get(&secret, `SELECT secret FROM credentials WHERE user_id = ? AND secret_type = 'public_key'`, userID)
	if err != nil {
		return nil, err
	}
	var pubKey map[string]string
	if err := json.Unmarshal([]byte(secret), &pubKey); err != nil {
		return nil, err
	}
	return pubKey, nil
}

// MFA methods implementation
func (v *DatabaseStorage) SetUserMFA(userID string, secret string, backupCodes []string) error {
	backupCodesJSON, _ := json.Marshal(backupCodes)
	_, err := v.db.Exec(`INSERT OR REPLACE INTO credentials (user_id, secret, secret_type, metadata) VALUES (?, ?, 'mfa', ?)`, userID, secret, string(backupCodesJSON))
	return err
}

func (v *DatabaseStorage) GetUserMFA(userID string) (string, []string, error) {
	var secret, metadata string
	err := v.db.QueryRow(`SELECT secret, metadata FROM credentials WHERE user_id = ? AND secret_type = 'mfa'`, userID).Scan(&secret, &metadata)
	if err != nil {
		return "", nil, err
	}
	var backupCodes []string
	if metadata != "" {
		json.Unmarshal([]byte(metadata), &backupCodes)
	}
	return secret, backupCodes, nil
}

func (v *DatabaseStorage) EnableMFA(userID string) error {
	_, err := v.db.Exec(`UPDATE users SET mfa_enabled = 1 WHERE user_id = ?`, userID)
	return err
}

func (v *DatabaseStorage) DisableMFA(userID string) error {
	_, err := v.db.Exec(`UPDATE users SET mfa_enabled = 0 WHERE user_id = ?`, userID)
	return err
}

func (v *DatabaseStorage) IsUserMFAEnabled(userID string) (bool, error) {
	var mfaEnabled bool
	err := v.db.QueryRow(`SELECT mfa_enabled FROM users WHERE user_id = ?`, userID).Scan(&mfaEnabled)
	if err != nil {
		return false, err
	}
	return mfaEnabled, nil
}

func (v *DatabaseStorage) ValidateBackupCode(userID, code string) error {
	secret, backupCodes, err := v.GetUserMFA(userID)
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
	return v.SetUserMFA(userID, secret, newBackupCodes)
}

func (v *DatabaseStorage) InvalidateBackupCode(userID, code string) error {
	return v.ValidateBackupCode(userID, code) // Same logic
}
