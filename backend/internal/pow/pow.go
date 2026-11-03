package pow

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

type Challenge struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

type Solution struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

func Issue(secret string, _ int) (Challenge, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Challenge{}, err
	}
	exp := time.Now().Add(15 * time.Minute).Unix()
	nonceHex := hex.EncodeToString(nonce)
	sig := sign(secret, nonceHex, exp)
	return Challenge{
		Token:     nonceHex + "." + sig,
		ExpiresAt: exp,
	}, nil
}

func Verify(secret string, sol Solution, _ int) bool {
	if sol.Token == "" || sol.ExpiresAt < time.Now().Unix() {
		return false
	}
	parts := strings.Split(sol.Token, ".")
	if len(parts) != 2 {
		return false
	}
	nonceHex, gotSig := parts[0], parts[1]
	return sign(secret, nonceHex, sol.ExpiresAt) == gotSig
}

func sign(secret, nonce string, exp int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(nonce + ":" + strconv.FormatInt(exp, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func EncodeSolution(sol Solution) string {
	b, _ := json.Marshal(sol)
	return string(b)
}

func DecodeSolution(raw string) (Solution, error) {
	raw = strings.TrimSpace(raw)
	var sol Solution
	if err := json.Unmarshal([]byte(raw), &sol); err == nil && sol.Token != "" {
		return sol, nil
	}
	var ch Challenge
	if err := json.Unmarshal([]byte(raw), &ch); err == nil && ch.Token != "" {
		return Solution{Token: ch.Token, ExpiresAt: ch.ExpiresAt}, nil
	}
	return Solution{}, errors.New("invalid pow")
}
