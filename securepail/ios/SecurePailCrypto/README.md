# SecurePailCrypto

The portable securePail encryption suite for iOS and macOS, in Swift with CryptoKit only. It reads and writes exactly the same files as the desktop app: `.spe` objects and `securepail-key` key files. The format is written down in [docs/secure-layer.md](../../docs/secure-layer.md).

```swift
import SecurePailCrypto

// Keys are "spk1-…" strings. Keep them in the Keychain, never in a file or log.
let key = SPE.generateKey()

// Small data in memory.
let object = try SPE.encrypt(Data("hello".utf8), key: key)
let plain  = try SPE.decrypt(object, key: key)

// Large files: one 1 MiB chunk at a time. Decryption writes to a temporary file
// and moves it into place only if every byte authenticated.
try SPE.encryptFile(at: source, to: destination, key: key)
try SPE.decryptFile(at: encrypted, to: destination, key: key)

// Backup: a password-protected key file (opens on the desktop too) and a recovery key.
let keyFile  = try KeyBackup.make(key: key, password: "…")
let restored = try KeyBackup.open(keyFile, password: "…")
let recovery = try KeyBackup.recoveryString(key: key)   // "A1B2-C3D4-…"
```

Only generated keys are supported; typed passphrases are a GPG-suite feature.

## Tests

```
swift test --package-path ios/SecurePailCrypto
```

The tests decrypt an object and open a key file that the Go desktop code wrote, re-create their bytes exactly, and check tampering, truncation, wrong keys, NFC passwords and file handling. The vectors in `Tests/SecurePailCryptoTests/Resources` are a copy of `internal/seclayer/testdata/portable-vectors.json`; a Go test fails when they differ.

Status: written without a Swift compiler available; CI (`.github/workflows/ios.yml`) is the first place it is built and tested.
