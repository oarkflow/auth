package main

import (
	"encoding/json"
	"fmt"

	"github.com/oarkflow/squealx"
	"github.com/oarkflow/squealx/drivers/sqlite"
)

// --- Vault Storage Interface ---
type VaultStorage interface {
	SetUserInfo(pubHex string, info UserInfo) error
	GetUserInfo(pubHex string) (UserInfo, error)
	GetUserInfoByUsername(username string) (UserInfo, error)
	SetUserSecret(userID, secret string) error
	GetUserSecret(userID string) (string, error)

	SetUserPublicKey(userID string, pubKeyX, pubKeyY string) error
	GetUserPublicKey(userID string) (map[string]string, error)
}

// --- SQLite Vault Storage ---
type SQLiteVaultStorage struct {
	db *squealx.DB
}

func NewSQLiteVaultStorage(dbPath string) (*SQLiteVaultStorage, error) {
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

	-- Phase 1: Add performance indexes
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
	CREATE INDEX IF NOT EXISTS idx_users_login_type ON users(login_type);
	CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active);
	CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
	CREATE INDEX IF NOT EXISTS idx_credentials_secret_type ON credentials(secret_type);

	-- Phase 1: Add audit log table
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

	return &SQLiteVaultStorage{db: db}, nil
}

func (v *SQLiteVaultStorage) SetUserInfo(pubHex string, info UserInfo) error {
	_, err := v.db.Exec(`INSERT OR REPLACE INTO users (pub_hex, username, user_id, login_type) VALUES (?, ?, ?, ?)`,
		pubHex, info.Username, info.UserID, info.LoginType)
	return err
}

func (v *SQLiteVaultStorage) GetUserInfo(pubHex string) (UserInfo, error) {
	var info UserInfo
	err := v.db.Get(&info, `SELECT user_id, username, login_type FROM users WHERE pub_hex = ?`, pubHex)
	if err != nil {
		return UserInfo{}, err
	}
	return info, nil
}

func (v *SQLiteVaultStorage) GetUserInfoByUsername(username string) (UserInfo, error) {
	var info UserInfo
	err := v.db.Get(&info, `SELECT user_id, username, login_type FROM users WHERE username = ?`, username)
	if err != nil {
		return UserInfo{}, err
	}
	return info, nil
}

func (v *SQLiteVaultStorage) SetUserSecret(userID, secret string) error {
	_, err := v.db.Exec(`INSERT OR REPLACE INTO credentials (user_id, secret, secret_type) VALUES (?, ?, 'password')`, userID, secret)
	return err
}

func (v *SQLiteVaultStorage) GetUserSecret(userID string) (string, error) {
	var secret string
	err := v.db.Get(&secret, `SELECT secret FROM credentials WHERE user_id = ? AND secret_type = 'password'`, userID)
	if err != nil {
		return "", err
	}
	return secret, nil
}

// New methods for public key storage
func (v *SQLiteVaultStorage) SetUserPublicKey(userID string, pubKeyX, pubKeyY string) error {
	pubKeyJSON, _ := json.Marshal(map[string]string{
		"PubKeyX": pubKeyX,
		"PubKeyY": pubKeyY,
	})
	_, err := v.db.Exec(`INSERT OR REPLACE INTO credentials (user_id, secret, secret_type) VALUES (?, ?, 'public_key')`, userID, string(pubKeyJSON))
	return err
}

func (v *SQLiteVaultStorage) GetUserPublicKey(userID string) (map[string]string, error) {
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
