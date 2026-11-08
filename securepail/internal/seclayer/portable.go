package seclayer

// The portable suite uses only primitives every platform ships: HKDF-SHA256,
// AES-256-GCM, PBKDF2-HMAC-SHA256. It follows the structure of the Quick Diary
// app (a random master key, wrapped by a password-derived key; AES-GCM boxes
// with fixed associated data) and adds a chunked layout for large files.
//
// Object format "SPE1":
//
//	header (24 bytes) = "SPE1" | chunkSize uint32 BE | salt (16 random bytes)
//	fileKey           = HKDF-SHA256(ikm = master key, salt = salt,
//	                                info = "securepail-file-v1", 32 bytes)
//	chunk i (i = 0,1,...) = AES-256-GCM(fileKey,
//	                                nonce = uint32 BE(i) | 7 zero bytes | last,
//	                                aad   = header,
//	                                plaintext = up to chunkSize bytes)
//	                        stored as ciphertext || 16-byte tag
//
// last is 1 for the final chunk and 0 for the others, so a truncated file
// fails to authenticate. The final chunk is the only one that may be shorter
// than chunkSize; an empty file is one empty chunk. The per-file key makes
// nonces unique without coordination between devices.
//
// Key file (JSON, same shape as Quick Diary's): see KeyFile.

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"
)

const (
	objMagic        = "SPE1"
	headerLen       = 4 + 4 + 16
	DefaultChunk    = 1 << 20
	minChunk        = 1 << 10
	maxChunk        = 16 << 20
	tagLen          = 16
	fileKeyInfo     = "securepail-file-v1"
	keyFileFormat   = "securepail-key"
	keyFileAAD      = "securepail-key-v1"
	keyCheckLabel   = "securepail-check"
	DefaultPBKDF2   = 600_000
	maxPBKDF2       = 10_000_000
	minPBKDF2       = 100_000
	masterKeyLength = 32
)

// Errors of the portable suite.
var (
	ErrNotPortable = &Error{Status: StatusNotEncrypted, Detail: "the object is not a securePail AES-GCM file"}
	ErrAuth        = &Error{Status: StatusTampered, Detail: "decryption failed (wrong key, or damaged or modified data)"}
)

// MasterKey decodes a generated key ("spk1-…") into its 32 bytes.
func MasterKey(secret string) ([]byte, error) {
	if !IsGeneratedKey(secret) {
		return nil, errors.New("the portable suite needs a generated key; create one with: pail secure keygen NAME")
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimPrefix(secret, keyPrefix))
}

func fileKey(master, salt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, master, salt, fileKeyInfo, 32)
}

func chunkAEAD(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func chunkNonce(i uint32, last bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n, i)
	if last {
		n[11] = 1
	}
	return n
}

// EncryptStream encrypts r into w with the generated key.
func EncryptStream(w io.Writer, r io.Reader, secret string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	return encryptStream(w, r, secret, salt, DefaultChunk)
}

func encryptStream(w io.Writer, r io.Reader, secret string, salt []byte, chunk int) error {
	master, err := MasterKey(secret)
	if err != nil {
		return err
	}
	fk, err := fileKey(master, salt)
	if err != nil {
		return err
	}
	aead, err := chunkAEAD(fk)
	if err != nil {
		return err
	}
	header := make([]byte, headerLen)
	copy(header, objMagic)
	binary.BigEndian.PutUint32(header[4:], uint32(chunk))
	copy(header[8:], salt)
	if _, err := w.Write(header); err != nil {
		return err
	}
	br := bufio.NewReaderSize(r, chunk+1)
	buf := make([]byte, chunk)
	for i := uint32(0); ; i++ {
		n, err := io.ReadFull(br, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		last := err != nil // short or empty read: this is the final chunk
		if !last {
			if _, perr := br.Peek(1); perr == io.EOF {
				last = true
			} else if perr != nil {
				return perr
			}
		}
		if i == ^uint32(0) && !last {
			return errors.New("file too large")
		}
		if _, err := w.Write(aead.Seal(nil, chunkNonce(i, last), buf[:n], header)); err != nil {
			return err
		}
		if last {
			return nil
		}
	}
}

// DecryptStream decrypts r into w. Output is written chunk by chunk after
// each chunk authenticates, but the stream is only trustworthy if the call
// returns nil (truncation is detected at the end): callers keep the output in
// a temporary file until then.
func DecryptStream(w io.Writer, r io.Reader, secret string) error {
	master, err := MasterKey(secret)
	if err != nil {
		return err
	}
	br := bufio.NewReaderSize(r, 64<<10)
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(br, header); err != nil || string(header[:4]) != objMagic {
		return ErrNotPortable
	}
	chunk := int(binary.BigEndian.Uint32(header[4:]))
	if chunk < minChunk || chunk > maxChunk {
		return ErrNotPortable
	}
	fk, err := fileKey(master, header[8:])
	if err != nil {
		return err
	}
	aead, err := chunkAEAD(fk)
	if err != nil {
		return err
	}
	buf := make([]byte, chunk+tagLen)
	for i := uint32(0); ; i++ {
		n, err := io.ReadFull(br, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		if n < tagLen {
			return ErrAuth
		}
		last := err != nil
		if !last {
			if _, perr := br.Peek(1); perr == io.EOF {
				last = true
			}
		}
		plain, oerr := aead.Open(nil, chunkNonce(i, last), buf[:n], header)
		if oerr != nil {
			return ErrAuth
		}
		if _, err := w.Write(plain); err != nil {
			return err
		}
		if last {
			return nil
		}
	}
}

// ---- key file --------------------------------------------------------------

// KeyFile is the password-protected backup of a master key (JSON). It has the
// shape of Quick Diary's key file: a random master key wrapped with
// AES-256-GCM under a PBKDF2-derived key. Data fields are base64.
type KeyFile struct {
	Format     string    `json:"format"`
	Version    int       `json:"version"`
	KDF        string    `json:"kdf"`
	Iterations int       `json:"iterations"`
	Salt       []byte    `json:"salt"`
	WrappedKey []byte    `json:"wrappedKey"` // AES-GCM nonce(12) | ciphertext | tag(16)
	Check      []byte    `json:"check"`      // first 16 bytes of HMAC-SHA256(master, "securepail-check")
	Created    time.Time `json:"created"`
}

func deriveKEK(password string, salt []byte, iter int) ([]byte, error) {
	pw := norm.NFC.String(password)
	return pbkdf2.Key(sha256.New, pw, salt, iter, 32)
}

func checkValue(master []byte) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte(keyCheckLabel))
	return m.Sum(nil)[:16]
}

// MakeKeyFile wraps the generated key with password.
func MakeKeyFile(secret, password string, iterations int) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return makeKeyFile(secret, password, iterations, salt, nonce, time.Now())
}

func makeKeyFile(secret, password string, iterations int, salt, nonce []byte, now time.Time) ([]byte, error) {
	master, err := MasterKey(secret)
	if err != nil {
		return nil, err
	}
	if iterations < minPBKDF2 || iterations > maxPBKDF2 {
		return nil, fmt.Errorf("PBKDF2 iterations must be between %d and %d", minPBKDF2, maxPBKDF2)
	}
	kek, err := deriveKEK(password, salt, iterations)
	if err != nil {
		return nil, err
	}
	aead, err := chunkAEAD(kek)
	if err != nil {
		return nil, err
	}
	wrapped := aead.Seal(append([]byte(nil), nonce...), nonce, master, []byte(keyFileAAD))
	kf := KeyFile{Format: keyFileFormat, Version: 1, KDF: "PBKDF2-HMAC-SHA256", Iterations: iterations,
		Salt: salt, WrappedKey: wrapped, Check: checkValue(master), Created: now.UTC().Truncate(time.Second)}
	return json.MarshalIndent(kf, "", "  ")
}

// IsKeyFile reports whether data looks like a securePail key file.
func IsKeyFile(data []byte) bool {
	var kf KeyFile
	return json.Unmarshal(data, &kf) == nil && kf.Format == keyFileFormat
}

// OpenKeyFile unwraps a key file and returns the generated key.
func OpenKeyFile(data []byte, password string) (string, error) {
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil || kf.Format != keyFileFormat || kf.Version != 1 ||
		kf.KDF != "PBKDF2-HMAC-SHA256" || len(kf.WrappedKey) < 12+tagLen {
		return "", errors.New("this is not a securePail key file")
	}
	if kf.Iterations < minPBKDF2 || kf.Iterations > maxPBKDF2 {
		return "", errors.New("the key file has unreasonable PBKDF2 settings")
	}
	kek, err := deriveKEK(password, kf.Salt, kf.Iterations)
	if err != nil {
		return "", err
	}
	aead, err := chunkAEAD(kek)
	if err != nil {
		return "", err
	}
	master, err := aead.Open(nil, kf.WrappedKey[:12], kf.WrappedKey[12:], []byte(keyFileAAD))
	if err != nil {
		return "", ErrBadPassphrase
	}
	if subtle.ConstantTimeCompare(checkValue(master), kf.Check) != 1 {
		return "", errors.New("the key file is damaged")
	}
	return keyPrefix + base64.RawURLEncoding.EncodeToString(master), nil
}

// RecoveryString shows the master key as 16 groups of 4 hex digits, to write
// down or type on a phone: "A1B2-C3D4-…".
func RecoveryString(secret string) (string, error) {
	master, err := MasterKey(secret)
	if err != nil {
		return "", err
	}
	h := strings.ToUpper(hex.EncodeToString(master))
	parts := make([]string, 0, 16)
	for i := 0; i < len(h); i += 4 {
		parts = append(parts, h[i:i+4])
	}
	return strings.Join(parts, "-"), nil
}

// ParseRecovery is the inverse of RecoveryString; dashes and spaces are ignored.
func ParseRecovery(text string) (string, error) {
	var b strings.Builder
	for _, r := range strings.ToUpper(text) {
		switch {
		case r >= '0' && r <= '9', r >= 'A' && r <= 'F':
			b.WriteRune(r)
		case r == '-' || r == ' ' || r == '\n' || r == '\r' || r == '\t':
		default:
			return "", errors.New("a recovery key has 64 characters (0-9, A-F)")
		}
	}
	raw, err := hex.DecodeString(b.String())
	if err != nil || len(raw) != masterKeyLength {
		return "", errors.New("a recovery key has 64 characters (0-9, A-F)")
	}
	return keyPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}
