# Secure layer and readiness check

English | [简体中文](secure-layer.zh-CN.md)

## Secure layer

An upload rule can add a secure layer: each file is encrypted on your computer before it is uploaded, so the storage service sees only ciphertext and the file size. Layers apply in a fixed order: compress, then encrypt. Downloads with `--decode auto --secure-key REF` undo them in reverse. Server-side encryption (SSE) can be combined with it.

### Choose a suite

Run `pail secure suites` to list them. Pick by where you need to open the files.

| | AES-256-GCM (portable) | GPG (OpenPGP) |
|---|---|---|
| Rule value | `aesgcm` | `gpg` |
| Object key suffix | `.spe` | `.gpg` |
| Needs extra software | No | gpg 2.2 or newer |
| Desktop | Yes | Yes |
| iOS and Android | Yes (CryptoKit, `javax.crypto`) | No |
| Large files | Chunked and streamed; truncation is detected | Whole stream |
| Key | Generated key only | Generated key or typed passphrase |
| Open without securePail | Port of the format below | `gpg -d` |

Choose **AES-256-GCM** unless you need standard OpenPGP files. It is the suite to use when the same files must open on a phone.

### Keys

The key lives in the key store under a reference name, never in a rule, a log or object metadata.

- `pail secure keygen REF` makes a random 256-bit key (also **Create a new key** in the upload rules).
- `pail secure passphrase REF` stores a typed passphrase after a strength check. Only GPG accepts it, and it is slow on purpose (about 150 ms per file).
- `pail secure export REF FILE` writes a password-protected key file. The default `keyfile` format is JSON (PBKDF2-HMAC-SHA256, 600,000 rounds, AES-256-GCM) and needs no tools; `--format gpg` writes a file that `gpg -d` opens.
- `pail secure recovery REF` prints the key as 16 groups of 4 hex digits, to write down or type on a phone.
- `pail secure import REF FILE` restores from a key file (either format) or a recovery key. Keys are never overwritten. Without the key, encrypted data cannot be recovered.

### Fail closed

If a required tool or the key is missing, the upload fails; it never falls back to plain text. A wrong key, damaged data or a file in the wrong format is refused on download, and nothing is saved.

### Limits

- Encrypted uploads stage a temporary file the size of the original.
- Checksum comparison in sync jobs cannot match encrypted objects (every encryption differs); use size and time.
- Downloaded files keep the `.spe` or `.gpg` name.

### Format of the portable suite

For people porting it to another platform. Only HKDF-SHA256, AES-256-GCM and PBKDF2-HMAC-SHA256 are needed.

```
object   = header | chunk 0 | chunk 1 | ...
header   = "SPE1" | chunkSize (uint32 BE, 1 KiB to 16 MiB; default 1 MiB) | salt (16 random bytes)
fileKey  = HKDF-SHA256(ikm = master key, salt = salt, info = "securepail-file-v1", 32 bytes)
chunk i  = AES-256-GCM(fileKey, nonce = uint32 BE(i) | 7 zero bytes | last, aad = header, plaintext of up to chunkSize bytes)
           stored as ciphertext | 16-byte tag
```

`last` is 1 on the final chunk and 0 on the others; only the final chunk may be short, and an empty file is one empty chunk. A fresh salt gives every file its own key.

The key file is JSON with `format` `securepail-key`, `version` 1, `kdf` `PBKDF2-HMAC-SHA256`, `iterations`, `salt`, `wrappedKey` (AES-GCM nonce, ciphertext and tag; associated data `securepail-key-v1`) and `check` (the first 16 bytes of HMAC-SHA256 of `securepail-check` under the master key). The password is NFC-normalised first. This follows the Quick Diary app's key file, with its own labels.

`internal/seclayer/testdata/portable-vectors.json` holds known-answer vectors. `python3 scripts/check-portable-vectors.py` decrypts them with a separate implementation (the Python `cryptography` package); a port should pass the same vectors.

## Readiness check

`pail doctor` checks what the secure layer depends on and tells you how to fix each problem: gpg (found, version 2.2 or newer), a real encrypt-and-decrypt round trip (catches a gpg-agent that blocks non-interactive use), gpg-agent, the OS key store and the temporary directory. gpg counts as required only when an enabled rule uses the GPG suite; add `--require-gpg` to check before you enable one. The exit code is 1 when a required component fails; `--json` gives one event per check. The desktop upload rules show the same check under a secure layer (**Check components**). Set `SECUREPAIL_GPG` to use a gpg at a specific path.

### Servers and other machines without a desktop

Keys live in the system key store. On a Linux machine with no desktop (a server, a Raspberry Pi) there is none, and `pail doctor` reports the key store as failed. Use the encrypted vault instead: `pail vault init`, then `pail vault backend vault`, and pass `--vault-password-stdin` to commands that need keys (`secure`, `doctor`, `cp`, `ssync`). The AES-256-GCM suite then needs nothing else installed. This works the same on Linux x64 and Arm.

## Origin

securePail is a fork of [Pail](https://github.com/DejavuMoe/Pail) by Dejavu Moe, built on the same stack (Go and [MyGo](https://github.com/egoist/mygo)). The GPG suite follows the design of [s3vault](https://github.com/jstdlee/s3vault) and the portable suite that of [Quick Diary](https://github.com/jstdlee/quick-diary). It keeps the MIT license. Its configuration directory and key store entries are named `securePail`, so it can be installed beside Pail.
