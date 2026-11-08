package app

// Bounded preview of a file in a root. Nothing is previewed automatically; the
// caller asks for one file. Sizes are checked against the listed object size
// before anything is downloaded and again while streaming, and the plaintext
// stays in memory.

import (
	"bytes"
	"context"
	"errors"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/jstdlee/securePail/internal/seclayer"
	"github.com/jstdlee/securePail/internal/storage"
)

// PreviewKind is how the content should be shown.
type PreviewKind string

// Preview kinds.
const (
	PreviewText     PreviewKind = "text"
	PreviewImage    PreviewKind = "image"
	PreviewHex      PreviewKind = "hex"      // not valid UTF-8 / unknown type: first bytes as a hex dump
	PreviewTooLarge PreviewKind = "toolarge" // over the cap: offer download instead
)

// PreviewCaps are the size limits; zero values mean the defaults.
type PreviewCaps struct {
	TextBytes, ImageBytes, HexBytes int64
	ImageMegapixels                 int
	TextLines                       int
}

func (c PreviewCaps) norm() PreviewCaps {
	if c.TextBytes <= 0 {
		c.TextBytes = 2 << 20
	}
	if c.ImageBytes <= 0 {
		c.ImageBytes = 50 << 20
	}
	if c.HexBytes <= 0 {
		c.HexBytes = 64 << 10
	}
	if c.ImageMegapixels <= 0 {
		c.ImageMegapixels = 64
	}
	if c.TextLines <= 0 {
		c.TextLines = 50000
	}
	return c
}

// Preview is the result of SecurePreview.
type Preview struct {
	Kind   PreviewKind `json:"kind"`
	Path   string      `json:"path"`
	Size   int64       `json:"size"` // size of the stored object
	Reason string      `json:"reason,omitempty"`
	Data   []byte      `json:"-"`
	Width  int         `json:"width,omitempty"`
	Height int         `json:"height,omitempty"`
}

var textExts = map[string]bool{}
var imageExts = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true}

func init() {
	for _, e := range strings.Fields(".txt .md .markdown .json .yaml .yml .toml .ini .cfg .conf .log .csv .tsv .xml .html .htm .css .js .ts .go .py .rb .rs .c .h .cpp .hpp .java .kt .swift .sh .bash .zsh .sql .tex .rst") {
		textExts[e] = true
	}
}

type capBuffer struct {
	buf   []byte
	limit int64
	over  bool
}

// WriteAt lets the downloader fill the buffer; it refuses to grow past limit.
func (b *capBuffer) WriteAt(p []byte, off int64) (int, error) {
	end := off + int64(len(p))
	if end > b.limit {
		b.over = true
		return 0, errors.New("preview size limit")
	}
	if int64(len(b.buf)) < end {
		b.buf = append(b.buf, make([]byte, end-int64(len(b.buf)))...)
	}
	copy(b.buf[off:], p)
	return len(p), nil
}

// SecurePreview fetches and decrypts one file for display.
func (s *Service) SecurePreview(ctx context.Context, rootID, rel string, caps PreviewCaps) (Preview, error) {
	const op = "SecurePreview"
	caps = caps.norm()
	root, err := s.secureRoot(op, rootID)
	if err != nil {
		return Preview{}, err
	}
	run, err := s.newSecureRun(ctx, op, root)
	if err != nil {
		return Preview{}, err
	}
	ro, ok, err := run.headRemote(ctx, rel)
	if err != nil {
		return Preview{}, err
	}
	if !ok {
		return Preview{}, opErr(op, ErrNotFound, "%q is not in the vault", rel)
	}
	ext := strings.ToLower(path.Ext(rel))
	limit := caps.HexBytes
	switch {
	case textExts[ext]:
		limit = caps.TextBytes
	case imageExts[ext]:
		limit = caps.ImageBytes
	}
	// The stored object is a little larger than the plaintext (encryption overhead).
	if ro.size > limit+1<<16 {
		return Preview{Kind: PreviewTooLarge, Path: rel, Size: ro.size,
			Reason: "too large to preview; download it instead"}, nil
	}
	dl := &capBuffer{limit: ro.size + 1}
	in := &s3.GetObjectInput{Bucket: aws.String(root.Bucket), Key: aws.String(ro.key), IfMatch: aws.String(ro.etag)}
	if _, err := run.c.Download(ctx, in, dl, storage.TransferOptions{Size: ro.size}); err != nil {
		return Preview{}, classify(op, err)
	}
	data := dl.buf
	if ro.enc {
		var out bytes.Buffer
		lw := &capWriter{w: &out, left: limit + 1}
		var derr error
		if root.Method == seclayer.SuiteGPG {
			derr = gpgDecryptBytes(ctx, run.sc, data, lw)
		} else {
			derr = seclayer.DecryptStream(lw, ctxReader{ctx, bytes.NewReader(data)}, run.sc.key)
		}
		if derr != nil {
			if lw.hit {
				return Preview{Kind: PreviewTooLarge, Path: rel, Size: ro.size, Reason: "too large to preview; download it instead"}, nil
			}
			return Preview{}, classify(op, derr)
		}
		data = out.Bytes()
	}
	p := Preview{Path: rel, Size: ro.size}
	switch {
	case imageExts[ext]:
		cfg, _, ierr := image.DecodeConfig(bytes.NewReader(data))
		if ierr != nil {
			return hexPreview(p, data, caps), nil
		}
		if int64(cfg.Width)*int64(cfg.Height) > int64(caps.ImageMegapixels)*1_000_000 {
			p.Kind, p.Reason = PreviewTooLarge, "the image has too many pixels to preview"
			return p, nil
		}
		p.Kind, p.Data, p.Width, p.Height = PreviewImage, data, cfg.Width, cfg.Height
	case utf8.Valid(data) && bytes.Count(data, []byte{'\n'}) <= caps.TextLines && (textExts[ext] || ext == "" || looksText(data)):
		p.Kind, p.Data = PreviewText, data
	default:
		return hexPreview(p, data, caps), nil
	}
	return p, nil
}

func looksText(b []byte) bool {
	if len(b) > 4096 {
		b = b[:4096]
	}
	return utf8.Valid(b) && !bytes.Contains(b, []byte{0})
}

func hexPreview(p Preview, data []byte, caps PreviewCaps) Preview {
	if int64(len(data)) > caps.HexBytes {
		data = data[:caps.HexBytes]
	}
	p.Kind, p.Data = PreviewHex, data
	return p
}

// gpgDecryptBytes decrypts in-memory ciphertext with gpg (which reads a file).
func gpgDecryptBytes(ctx context.Context, sc *secureCtx, cipher []byte, w io.Writer) error {
	out, err := sc.gpg.DecryptBytes(ctx, cipher, sc.key, 1<<31-1)
	if err != nil {
		return err
	}
	_, err = w.Write(out)
	return err
}
