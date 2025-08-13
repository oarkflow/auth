package pkg

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

	// MFA methods
	SetUserMFA(userID string, secret string, backupCodes []string) error
	GetUserMFA(userID string) (string, []string, error)
	EnableMFA(userID string) error
	DisableMFA(userID string) error
	IsUserMFAEnabled(userID string) (bool, error)
	ValidateBackupCode(userID, code string) error
	InvalidateBackupCode(userID, code string) error

	// Central Authentication System methods
	CreateClient(client *Client) error
	GetClient(clientID string) (*Client, error)
	UpdateClient(client *Client) error
	ListClients() ([]*Client, error)

	CreateAuthorizationCode(code *AuthorizationCode) error
	GetAuthorizationCode(code string) (*AuthorizationCode, error)
	UseAuthorizationCode(code string) error

	CreateAccessToken(token *AccessToken) error
	GetAccessToken(token string) (*AccessToken, error)
	RevokeAccessToken(token string) error

	CreateRefreshToken(token *RefreshToken) error
	GetRefreshToken(token string) (*RefreshToken, error)
	RevokeRefreshToken(token string) error
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

	return &SQLiteVaultStorage{db: db}, nil
}

func (v *SQLiteVaultStorage) SetUserInfo(pubHex string, info UserInfo) error {
	_, err := v.db.Exec(`INSERT OR REPLACE INTO users (pub_hex, username, user_id, login_type, mfa_enabled) VALUES (?, ?, ?, ?, ?)`,
		pubHex, info.Username, info.UserID, info.LoginType, info.MFAEnabled)
	return err
}

func (v *SQLiteVaultStorage) GetUserInfo(pubHex string) (UserInfo, error) {
	var info UserInfo
	err := v.db.QueryRow(`SELECT user_id, username, login_type, mfa_enabled FROM users WHERE pub_hex = ?`, pubHex).Scan(
		&info.UserID, &info.Username, &info.LoginType, &info.MFAEnabled)
	if err != nil {
		return UserInfo{}, err
	}
	return info, nil
}

func (v *SQLiteVaultStorage) GetUserInfoByUsername(username string) (UserInfo, error) {
	var info UserInfo
	err := v.db.QueryRow(`SELECT user_id, username, login_type, mfa_enabled FROM users WHERE username = ?`, username).Scan(
		&info.UserID, &info.Username, &info.LoginType, &info.MFAEnabled)
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

// Central Authentication System methods implementation
func (v *SQLiteVaultStorage) CreateClient(client *Client) error {
	redirectURIsJSON, _ := json.Marshal(client.RedirectURIs)
	scopesJSON, _ := json.Marshal(client.Scopes)

	_, err := v.db.Exec(`INSERT INTO clients (client_id, client_secret, name, redirect_uris, scopes, is_approved) VALUES (?, ?, ?, ?, ?, ?)`,
		client.ClientID, client.ClientSecret, client.Name, string(redirectURIsJSON), string(scopesJSON), client.IsApproved)
	return err
}

func (v *SQLiteVaultStorage) GetClient(clientID string) (*Client, error) {
	var client Client
	var redirectURIsJSON, scopesJSON string

	err := v.db.QueryRow(`SELECT client_id, client_secret, name, redirect_uris, scopes, is_approved, created_at, updated_at FROM clients WHERE client_id = ?`, clientID).Scan(
		&client.ClientID, &client.ClientSecret, &client.Name, &redirectURIsJSON, &scopesJSON, &client.IsApproved, &client.CreatedAt, &client.UpdatedAt)
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(redirectURIsJSON), &client.RedirectURIs)
	json.Unmarshal([]byte(scopesJSON), &client.Scopes)

	return &client, nil
}

func (v *SQLiteVaultStorage) UpdateClient(client *Client) error {
	redirectURIsJSON, _ := json.Marshal(client.RedirectURIs)
	scopesJSON, _ := json.Marshal(client.Scopes)

	_, err := v.db.Exec(`UPDATE clients SET name = ?, redirect_uris = ?, scopes = ?, is_approved = ?, updated_at = CURRENT_TIMESTAMP WHERE client_id = ?`,
		client.Name, string(redirectURIsJSON), string(scopesJSON), client.IsApproved, client.ClientID)
	return err
}

func (v *SQLiteVaultStorage) ListClients() ([]*Client, error) {
	rows, err := v.db.Query(`SELECT client_id, client_secret, name, redirect_uris, scopes, is_approved, created_at, updated_at FROM clients ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []*Client
	for rows.Next() {
		var client Client
		var redirectURIsJSON, scopesJSON string

		err := rows.Scan(&client.ClientID, &client.ClientSecret, &client.Name, &redirectURIsJSON, &scopesJSON, &client.IsApproved, &client.CreatedAt, &client.UpdatedAt)
		if err != nil {
			return nil, err
		}

		json.Unmarshal([]byte(redirectURIsJSON), &client.RedirectURIs)
		json.Unmarshal([]byte(scopesJSON), &client.Scopes)

		clients = append(clients, &client)
	}

	return clients, nil
}

func (v *SQLiteVaultStorage) CreateAuthorizationCode(code *AuthorizationCode) error {
	scopesJSON, _ := json.Marshal(code.Scopes)

	_, err := v.db.Exec(`INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		code.Code, code.ClientID, code.UserID, code.RedirectURI, string(scopesJSON), code.ExpiresAt)
	return err
}

func (v *SQLiteVaultStorage) GetAuthorizationCode(code string) (*AuthorizationCode, error) {
	var authCode AuthorizationCode
	var scopesJSON string

	err := v.db.QueryRow(`SELECT code, client_id, user_id, redirect_uri, scopes, expires_at, used FROM authorization_codes WHERE code = ?`, code).Scan(
		&authCode.Code, &authCode.ClientID, &authCode.UserID, &authCode.RedirectURI, &scopesJSON, &authCode.ExpiresAt, &authCode.Used)
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(scopesJSON), &authCode.Scopes)

	return &authCode, nil
}

func (v *SQLiteVaultStorage) UseAuthorizationCode(code string) error {
	_, err := v.db.Exec(`UPDATE authorization_codes SET used = 1 WHERE code = ?`, code)
	return err
}

func (v *SQLiteVaultStorage) CreateAccessToken(token *AccessToken) error {
	scopesJSON, _ := json.Marshal(token.Scopes)

	_, err := v.db.Exec(`INSERT INTO access_tokens (token, client_id, user_id, scopes, expires_at) VALUES (?, ?, ?, ?, ?)`,
		token.Token, token.ClientID, token.UserID, string(scopesJSON), token.ExpiresAt)
	return err
}

func (v *SQLiteVaultStorage) GetAccessToken(token string) (*AccessToken, error) {
	var accessToken AccessToken
	var scopesJSON string

	err := v.db.QueryRow(`SELECT token, client_id, user_id, scopes, expires_at, created_at FROM access_tokens WHERE token = ?`, token).Scan(
		&accessToken.Token, &accessToken.ClientID, &accessToken.UserID, &scopesJSON, &accessToken.ExpiresAt, &accessToken.CreatedAt)
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(scopesJSON), &accessToken.Scopes)

	return &accessToken, nil
}

func (v *SQLiteVaultStorage) RevokeAccessToken(token string) error {
	_, err := v.db.Exec(`DELETE FROM access_tokens WHERE token = ?`, token)
	return err
}

func (v *SQLiteVaultStorage) CreateRefreshToken(token *RefreshToken) error {
	_, err := v.db.Exec(`INSERT INTO refresh_tokens (token, client_id, user_id, expires_at) VALUES (?, ?, ?, ?)`,
		token.Token, token.ClientID, token.UserID, token.ExpiresAt)
	return err
}

func (v *SQLiteVaultStorage) GetRefreshToken(token string) (*RefreshToken, error) {
	var refreshToken RefreshToken

	err := v.db.QueryRow(`SELECT token, client_id, user_id, expires_at, created_at FROM refresh_tokens WHERE token = ?`, token).Scan(
		&refreshToken.Token, &refreshToken.ClientID, &refreshToken.UserID, &refreshToken.ExpiresAt, &refreshToken.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &refreshToken, nil
}

func (v *SQLiteVaultStorage) RevokeRefreshToken(token string) error {
	_, err := v.db.Exec(`DELETE FROM refresh_tokens WHERE token = ?`, token)
	return err
}

// MFA methods implementation
func (v *SQLiteVaultStorage) SetUserMFA(userID string, secret string, backupCodes []string) error {
	backupCodesJSON, _ := json.Marshal(backupCodes)
	_, err := v.db.Exec(`INSERT OR REPLACE INTO credentials (user_id, secret, secret_type, metadata) VALUES (?, ?, 'mfa', ?)`, userID, secret, string(backupCodesJSON))
	return err
}

func (v *SQLiteVaultStorage) GetUserMFA(userID string) (string, []string, error) {
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

func (v *SQLiteVaultStorage) EnableMFA(userID string) error {
	_, err := v.db.Exec(`UPDATE users SET mfa_enabled = 1 WHERE user_id = ?`, userID)
	return err
}

func (v *SQLiteVaultStorage) DisableMFA(userID string) error {
	_, err := v.db.Exec(`UPDATE users SET mfa_enabled = 0 WHERE user_id = ?`, userID)
	return err
}

func (v *SQLiteVaultStorage) IsUserMFAEnabled(userID string) (bool, error) {
	var mfaEnabled bool
	err := v.db.QueryRow(`SELECT mfa_enabled FROM users WHERE user_id = ?`, userID).Scan(&mfaEnabled)
	if err != nil {
		return false, err
	}
	return mfaEnabled, nil
}

func (v *SQLiteVaultStorage) ValidateBackupCode(userID, code string) error {
	secret, backupCodes, err := v.GetUserMFA(userID)
	if err != nil {
		return err
	}

	// Check if code exists in backup codes
	found := false
	newBackupCodes := []string{}
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

func (v *SQLiteVaultStorage) InvalidateBackupCode(userID, code string) error {
	return v.ValidateBackupCode(userID, code) // Same logic
}
