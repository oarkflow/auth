package libs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/oarkflow/auth/pkg/models"
)

// --- Cryptographic Functions ---
func MakeProof(priv *ecdsa.PrivateKey, nonce string, ts int64) (models.SchnorrProof, error) {
	curve := priv.PublicKey.Curve
	r, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return models.SchnorrProof{}, fmt.Errorf("rand.Int: %w", err)
	}
	Rx, Ry := curve.ScalarBaseMult(r.Bytes())
	h := sha256.New()
	h.Write(Rx.Bytes())
	h.Write(Ry.Bytes())
	h.Write([]byte(nonce))
	h.Write([]byte(fmt.Sprintf("%d", ts)))
	c := new(big.Int).SetBytes(h.Sum(nil))
	c.Mod(c, curve.Params().N)
	sx := new(big.Int).Mul(c, priv.D)
	s := new(big.Int).Add(r, sx)
	s.Mod(s, curve.Params().N)
	return models.SchnorrProof{
		R:       hex.EncodeToString(append(Rx.Bytes(), Ry.Bytes()...)),
		S:       hex.EncodeToString(s.Bytes()),
		PubKeyX: fmt.Sprintf("%064x", priv.PublicKey.X),
		PubKeyY: fmt.Sprintf("%064x", priv.PublicKey.Y),
		Nonce:   nonce,
		Ts:      ts,
	}, nil
}

func GenerateProof(privateKey string, nonce string, ts int64) models.SchnorrProof {
	privD, err := hex.DecodeString(privateKey)
	if err != nil {
		return models.SchnorrProof{}
	}
	curve := elliptic.P256()
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = new(big.Int).SetBytes(privD)
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(priv.D.Bytes())
	proof, err := MakeProof(priv, nonce, ts)
	if err != nil {
		return models.SchnorrProof{}
	}
	return proof
}

func VerifyProof(p *models.SchnorrProof) error {
	now := time.Now().Unix()
	if now-p.Ts > 60 || p.Ts-now > 5 {
		return fmt.Errorf("timestamp outside window")
	}
	rb, err := hex.DecodeString(p.R)
	if err != nil || len(rb) != 64 {
		return fmt.Errorf("invalid R encoding")
	}
	sx, err := hex.DecodeString(p.S)
	if err != nil {
		return fmt.Errorf("invalid S encoding")
	}
	pubXb, err := hex.DecodeString(p.PubKeyX)
	if err != nil {
		return fmt.Errorf("invalid PubKeyX encoding")
	}
	pubYb, err := hex.DecodeString(p.PubKeyY)
	if err != nil {
		return fmt.Errorf("invalid PubKeyY encoding")
	}
	Rx := new(big.Int).SetBytes(rb[:32])
	Ry := new(big.Int).SetBytes(rb[32:])
	s := new(big.Int).SetBytes(sx)
	pubX := new(big.Int).SetBytes(pubXb)
	pubY := new(big.Int).SetBytes(pubYb)
	curve := elliptic.P256()
	h := sha256.New()
	h.Write(Rx.Bytes())
	h.Write(Ry.Bytes())
	h.Write([]byte(p.Nonce))
	h.Write([]byte(fmt.Sprintf("%d", p.Ts)))
	c := new(big.Int).SetBytes(h.Sum(nil))
	c.Mod(c, curve.Params().N)
	Lx, Ly := curve.ScalarBaseMult(s.Bytes())
	Cx, Cy := curve.ScalarMult(pubX, pubY, c.Bytes())
	Rx2, Ry2 := curve.Add(Rx, Ry, Cx, Cy)
	lxBytes := Lx.Bytes()
	rx2Bytes := Rx2.Bytes()
	lyBytes := Ly.Bytes()
	ry2Bytes := Ry2.Bytes()
	if len(lxBytes) != len(rx2Bytes) {
		if len(lxBytes) < len(rx2Bytes) {
			tmp := make([]byte, len(rx2Bytes))
			copy(tmp[len(rx2Bytes)-len(lxBytes):], lxBytes)
			lxBytes = tmp
		} else {
			tmp := make([]byte, len(lxBytes))
			copy(tmp[len(lxBytes)-len(rx2Bytes):], rx2Bytes)
			rx2Bytes = tmp
		}
	}
	if len(lyBytes) != len(ry2Bytes) {
		if len(lyBytes) < len(ry2Bytes) {
			tmp := make([]byte, len(ry2Bytes))
			copy(tmp[len(ry2Bytes)-len(lyBytes):], lyBytes)
			lyBytes = tmp
		} else {
			tmp := make([]byte, len(lyBytes))
			copy(tmp[len(lyBytes)-len(ry2Bytes):], ry2Bytes)
			ry2Bytes = tmp
		}
	}
	if subtle.ConstantTimeCompare(lxBytes, rx2Bytes) != 1 || subtle.ConstantTimeCompare(lyBytes, ry2Bytes) != 1 {
		return fmt.Errorf("invalid Schnorr proof")
	}
	return nil
}

func GenerateKeyPair() (string, string, string) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKeyX := hex.EncodeToString(priv.PublicKey.X.Bytes())
	pubKeyY := hex.EncodeToString(priv.PublicKey.Y.Bytes())
	privD := hex.EncodeToString(priv.D.Bytes())
	return pubKeyX, pubKeyY, privD
}

// --- Helper Functions ---
func PadHex(s string) string {
	return fmt.Sprintf("%064s", strings.ToLower(s))
}

func VerifyProofWithReplay(manager *Manager, p *models.SchnorrProof) error {
	manager.CleanupExpiredNonces()
	if manager.IsNonceReplayed(p.Nonce) {
		return fmt.Errorf("nonce replayed")
	}
	return VerifyProof(p)
}
