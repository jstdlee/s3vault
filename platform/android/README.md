# Android backend (reserved)

Flutter UI (`app/mobile`) over the C++ core via `dart:ffi` (NDK build of `core/`).

- Crypto: RNP backend (same OpenPGP format as the desktop gpg CLI).
- Secrets: Android Keystore (wrap the vault key with a Keystore AES key; optional biometric gate).
- Folders: Storage Access Framework tree URIs; periodic sync with WorkManager; no live watching.
- Temp plaintext: app cache dir, scrubbed on close.
