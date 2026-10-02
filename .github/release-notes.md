Built from `@SHA@` by GitHub Actions.

| Download | System |
|---|---|
| `s3vault-*-linux-x86_64.tar.gz` | Linux, Intel/AMD 64-bit |
| `s3vault-*-linux-arm64.tar.gz` | Linux, ARM 64-bit (e.g. Raspberry Pi 5, Graviton, GB10) |
| `s3vault-*-windows-x86_64.zip` | Windows 10/11, 64-bit |

Each file has a `.sha256` next to it.

**Linux:** `tar xzf s3vault-*-linux-<arch>.tar.gz`, then run `bin/s3vault` (desktop app) or `bin/s3vault-cli`.
Needs libcurl4 and gnupg ≥ 2.2. Optional: poppler-utils (PDF preview) and a Secret Service keyring.

**Windows:** unzip, then run `s3vault.exe` (desktop app) or `s3vault-cli.exe`.
Needs [Gpg4win](https://gpg4win.org) (or GnuPG for Windows) ≥ 2.2. libcurl ships in the zip. Passwords you ask
s3vault to remember go to the Windows Credential Manager. The build is not code-signed yet, so SmartScreen may warn
on first start: choose *More info → Run anyway*.
