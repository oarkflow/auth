package pkg

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

// GenerateMFASecret generates a new TOTP secret for a user and returns the secret and QR code as base64 image
func GenerateMFASecret(username, issuer string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP key: %w", err)
	}

	// Generate QR code as PNG image
	qrURL := key.URL()
	qrPNG, err := qrcode.Encode(qrURL, qrcode.Medium, 256)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate QR code: %w", err)
	}

	// Convert to base64 data URL for HTML embedding
	qrCodeDataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(qrPNG)
	secret := key.Secret()

	return secret, qrCodeDataURL, nil
}

// VerifyMFACode validates a TOTP code against the user's secret
func VerifyMFACode(code, secret string) bool {
	return totp.Validate(code, secret)
}

// GenerateBackupCodes generates backup codes for MFA
func GenerateBackupCodes(count int) ([]string, error) {
	codes := make([]string, count)

	for i := 0; i < count; i++ {
		// Generate 8 random bytes
		bytes := make([]byte, 8)
		if _, err := rand.Read(bytes); err != nil {
			return nil, fmt.Errorf("failed to generate random bytes: %w", err)
		}

		// Encode as base32 and format as backup code
		code := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes))
		// Format as XXXX-XXXX
		if len(code) >= 8 {
			codes[i] = fmt.Sprintf("%s-%s", code[:4], code[4:8])
		} else {
			codes[i] = code
		}
	}

	return codes, nil
}

// ValidateMFAInput validates MFA code format
func ValidateMFAInput(code string) error {
	// Remove spaces and convert to uppercase
	code = strings.ReplaceAll(strings.ToUpper(code), " ", "")

	// TOTP codes are typically 6 digits
	if len(code) == 6 {
		for _, char := range code {
			if char < '0' || char > '9' {
				return fmt.Errorf("invalid TOTP code format")
			}
		}
		return nil
	}

	// Backup codes are in format XXXX-XXXX (with or without dash)
	if len(code) == 8 || len(code) == 9 {
		// Could be backup code format
		return nil
	}

	return fmt.Errorf("invalid MFA code format")
}

// IsBackupCodeFormat checks if the provided code looks like a backup code
func IsBackupCodeFormat(code string) bool {
	// Remove spaces and convert to lowercase
	code = strings.ReplaceAll(strings.ToLower(code), " ", "")

	// Backup codes can be XXXXXXXX or XXXX-XXXX
	if len(code) == 8 || len(code) == 9 {
		return true
	}

	return false
}

// FormatBackupCode formats a backup code consistently
func FormatBackupCode(code string) string {
	// Remove spaces and dashes, convert to lowercase
	code = strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(code), " ", ""), "-", "")

	// Format as XXXX-XXXX if it's 8 characters
	if len(code) == 8 {
		return fmt.Sprintf("%s-%s", code[:4], code[4:])
	}

	return code
}
