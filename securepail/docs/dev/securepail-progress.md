# securePail progress

Where the fork of [Pail](https://github.com/DejavuMoe/Pail) stands, what was checked and how, and what is open. Written 2026-11-08.

## Done

| Area | What | Where |
|---|---|---|
| Fork | Module `github.com/jstdlee/securePail`; config directory and key store entries named `securePail` so it installs beside Pail | `go.mod`, `internal/app/service.go`, `secrets.go` |
| Secure layer, GPG suite | Files encrypted with the `gpg` tool before upload; passphrase on stdin only; integrity enforced; fails closed | `internal/seclayer/gpg.go` |
| Secure layer, portable suite | AES-256-GCM, per-file HKDF key, 1 MiB chunks with a last-chunk flag; PBKDF2 key file; recovery key | `internal/seclayer/portable.go`, `docs/secure-layer.md` |
| Suite choice | `aesgcm` or `gpg` per upload rule and per sync root; `pail secure suites` | `internal/seclayer/suite.go`, `internal/rules` |
| Readiness check | `pail doctor`, desktop "Check components": gpg version and a real round trip, gpg-agent, key store, temp dir | `internal/readiness` |
| Secure sync | Two-way sync, conflicts, remote trash, edit with save-back, bounded preview, device registry | `internal/vsync`, `internal/app/securesync*.go`, `cmd/pail/cmds_ssync.go`, desktop tool `ssync_tool.go`, `docs/secure-sync.md` |
| iOS | Swift package for the portable suite and key file | `ios/SecurePailCrypto` |
| Linux arm64 | Built, released and tested; headless machines use the encrypted vault | `docs/dev/ci.md`, `cmd/pail/vault.go` |
| CI scope | Windows and Linux only; macOS jobs removed | `.github/workflows/` |

## Verified, and at which layer

| Claim | Layer | Evidence |
|---|---|---|
| Suites, planner, sync engine, conflicts, trash, edit, preview | Protocol tests against the in-memory S3 server (`internal/s3test`) | `go test ./...` passes on linux/amd64, including a three-device random simulation and a lost-race case |
| GPG suite | Real `gpg` 2.x on linux/amd64, isolated `GNUPGHOME` | `internal/seclayer`, `internal/app/secure_test.go` |
| Portable format is portable | Independent implementation | `python3 scripts/check-portable-vectors.py` (Python `cryptography`) decrypts the Go-written vectors and key file |
| linux/arm64 | Emulated CPU (`qemu-aarch64-static`), not hardware | seclayer, vsync, readiness, rules, `cmd/pail` and the app secure/sync tests pass; the shipped static arm64 `pail` runs `version`, `secure suites`, `doctor` and the vault-backed `secure keygen`; `tools/release -targets linux/amd64,linux/arm64` builds and verifies |
| Desktop tool and rules form | Headless UI tests | `go test ./cmd/pail-desktop` |

## Not verified

- **Swift code has never been compiled or run.** There is no Swift toolchain in the development container. Only a syntax parse (tree-sitter) was done. The first real build is the macOS job in `.github/workflows/ios.yml` (and the scratch copy in `s3vault`, below).
- GPG tests did not run on arm64: the host `gpg` is x86 and cannot run inside the emulator.
- The arm64 desktop app was not started (the emulator has no arm64 system libraries); no real GUI session on any platform.
- Nothing was run against a real S3, R2 or MinIO endpoint, or on Windows.

## Open

- **The `securePail` repository does not exist on GitHub**, and the development session may not create repositories. This tree has only the `upstream` remote (Pail). Create `jstdlee/securePail`, then `git remote add origin … && git push -u origin main`.
- **iOS CI has not run.** A scratch copy of the package and workflow was pushed to `jstdlee/s3vault`, branch `claude/securepail-readiness-check-numt1w` (`securepail-ios/`, `.github/workflows/securepail-ios.yml`). Pushes from the development session did not trigger Actions, and `workflow_dispatch` returned 404 because the workflow is not on `main`. Either run it from a repository where the workflow is on the default branch, or push this tree to the real repository (`ios.yml` runs on push).
- Adding a sync root is command-line only; the desktop tool manages existing roots.
- No file-system watcher (`pail ssync watch` polls); no PDF preview; s3vault's password cache modes (ask, idle, keychain days) are not repeated.
- No iOS app yet, only the crypto package. No Android.
- Release archives and the landing-page tools still carry Pail's names and six-platform lists.

## Resume

```
go vet ./... && go test ./...                          # amd64
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -exec qemu-aarch64-static ./internal/... ./cmd/pail
python3 scripts/check-portable-vectors.py
swift test --package-path ios/SecurePailCrypto         # macOS only
```
