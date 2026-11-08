package seclayer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"unicode"
)

// A secure-layer secret is one of two kinds, told apart by the value itself:
//
//   - a generated vault key ("spk1-" + 32 random bytes, base64url): high
//     entropy, so gpg uses fast salted S2K (a few milliseconds per file);
//   - a human passphrase: gpg uses iterated S2K at the maximum count, which
//     is deliberately slow (about 150 ms per file).
const keyPrefix = "spk1-"

// GenerateKey returns a new random vault key.
func GenerateKey() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return keyPrefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// IsGeneratedKey reports whether v is a well-formed generated vault key.
func IsGeneratedKey(v string) bool {
	if !strings.HasPrefix(v, keyPrefix) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(v, keyPrefix))
	return err == nil && len(raw) == 32
}

// StrongS2K reports whether a secret needs the slow iterated S2K.
func StrongS2K(secret string) bool { return !IsGeneratedKey(secret) }

// WrapKey protects a secret (usually a generated key) with a password, giving
// a key file that gpg alone can open: `gpg -d key.gpg`. It is the backup
// format; a password change only re-wraps this file.
func (g *GPG) WrapKey(ctx context.Context, secret, password string) ([]byte, error) {
	return g.EncryptBytes(ctx, []byte(secret), password, true)
}

// UnwrapKey opens a key file produced by WrapKey.
func (g *GPG) UnwrapKey(ctx context.Context, wrapped []byte, password string) (string, error) {
	b, err := g.DecryptBytes(ctx, wrapped, password, 4096)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// MinPasswordLength is the shortest accepted human passphrase.
const MinPasswordLength = 14

// Strength is a rough password estimate.
type Strength struct {
	Score      int // 0..4, 3 or more is accepted
	Problems   []string
	Acceptable bool
}

var common = []string{"password", "passw0rd", "letmein", "welcome", "qwerty", "admin", "iloveyou", "123456", "abcdef", "monkey", "dragon", "secret"}

// CheckPassword estimates a passphrase: length, character classes, repeats,
// common words and keyboard or alphabet runs.
func CheckPassword(pw string) Strength {
	var s Strength
	rs := []rune(pw)
	if len(rs) < MinPasswordLength {
		s.Problems = append(s.Problems, "use at least 14 characters")
	}
	var lower, upper, digit, other bool
	distinct := map[rune]bool{}
	for _, r := range rs {
		distinct[r] = true
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, c := range []bool{lower, upper, digit, other} {
		if c {
			classes++
		}
	}
	low := strings.ToLower(pw)
	for _, w := range common {
		if strings.Contains(low, w) {
			s.Problems = append(s.Problems, "contains a common word")
			break
		}
	}
	if len(rs) > 0 && len(distinct)*3 < len(rs) {
		s.Problems = append(s.Problems, "too many repeated characters")
	}
	if hasRun(rs) {
		s.Problems = append(s.Problems, "contains a sequence such as abcd or 1234")
	}
	score := 0
	switch {
	case len(rs) >= 20:
		score = 4
	case len(rs) >= 16:
		score = 3
	case len(rs) >= MinPasswordLength:
		score = 2
	case len(rs) >= 10:
		score = 1
	}
	if classes >= 3 && score < 4 {
		score++
	}
	if classes == 1 && score > 2 {
		score--
	}
	score -= len(s.Problems)
	if len(rs) < MinPasswordLength {
		score = min(score, 1)
	}
	s.Score = max(0, min(4, score))
	s.Acceptable = s.Score >= 3 && len(s.Problems) == 0
	return s
}

func hasRun(rs []rune) bool {
	for i := 0; i+3 < len(rs); i++ {
		d := rs[i+1] - rs[i]
		if (d == 1 || d == -1) && rs[i+2]-rs[i+1] == d && rs[i+3]-rs[i+2] == d {
			return true
		}
	}
	return false
}
