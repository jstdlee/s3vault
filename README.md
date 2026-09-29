# s3vault

Sync files between your devices through any S3-compatible storage: Cloudflare R2, AWS S3, MinIO, Backblaze B2, Wasabi and others. Each file can be encrypted with standard OpenPGP by the `gpg` you already have. Conflicts are never resolved silently: you review them, grouped by folder, and apply one decision to many files at once.

Linux desktop app: C++17, Dear ImGui, GLFW, OpenGL 3.3. This is the same stack as [gpu-hud](../gpu-hud). There is also a headless `s3vault-cli`. The source tree has room for macOS, Windows, iOS and Android (see [Platforms](#platforms)).

## Features

- **Tracked folders.** Two-way, upload-only (backup) or download-only (mirror) sync. Local changes are picked up by inotify, with a periodic rescan as a safety net. The server is polled every 60 s. Each folder can have a `.s3vaultignore` file (gitignore syntax).
- **Vault browser.** A tree of folders and files with type icons, sortable by name, type, size, last modified and sync status. You can filter by name or by type (text, images, PDF, encrypted).
- **File operations.** Upload (built-in file browser with multi-select, or drag and drop; folders included), new folder, rename/move (a server-side copy, so nothing is re-uploaded), delete to the vault trash, restore, and download to a location you choose.
- **Preview on click only.** Supported types are text/code, images (png/jpg/gif/bmp/tga/psd) and PDF (one page at a time). Nothing is downloaded or decrypted until you ask. There are hard size limits. The plaintext is wiped when the preview closes, when you select something else, when the vault locks, or after 2 minutes idle.
- **Built-in viewer and editor only.** Text, image and PDF previews and the text editor all run inside s3vault. Decrypted content stays in memory: it is never written to disk and never handed to another program (there is no "open with"). PDFs are piped to poppler through `fd://0`. The editor (Editor tab, Ctrl+S) saves back with `If-Match`. If the server copy changed since you opened it, you choose **Keep both / Overwrite server / Reload server version**. Closing with unsaved changes asks first.
- **Conflicts.** A file changed on two devices, or changed on one and deleted on the other, is listed under **Conflicts**, grouped by tracked folder → parent folder → file. Checkboxes at every level let you apply **Keep both / Overwrite server / Overwrite local / Keep newest** to a whole group. **Compare** shows the two versions side by side.
- **Password and lock.** New passwords need at least 14 characters and must pass a strength check; there is a generator too. **Lock** (manually, or after N idle minutes) hides the window behind a password screen, but the vault key stays in locked memory so sync, including encrypted files, keeps running. **Forget vault key** stops encrypted sync until you unlock. The key can also be kept in the keychain for N days.
- **Dependencies are configurable:** the `gpg` and `pdftoppm` paths. The S3 secret goes in the keychain (libsecret), or in `$S3VAULT_SECRET_KEY`.

## How it works

### Storage layout

This is one prefix in one bucket, for example `s3vault/main/`. The layout is plain enough that other S3 tools can list and fetch it:

```
.s3vault/vault.json          format, id, creator (no secrets)
.s3vault/key.gpg             random vault key, gpg-encrypted with your password
.s3vault/trash/<ts>/<path>   deleted objects (purge after N days)
<path>                       plain file
<path>.gpg                   encrypted file (OpenPGP symmetric, AES-256)
<dir>/                       empty folder marker
```

s3vault stores no custom metadata. Sync uses only what S3 already returns: key, size, ETag and LastModified.

### Sync: a 3-way compare plus conditional writes

For every file, the local index stores `base`: the ETag and plaintext SHA-256 from the last sync.

| local vs base | server vs base | action |
|---|---|---|
| changed | same | upload with `If-Match: <ETag>` |
| same | changed | download (temp file + atomic rename) |
| changed | changed | download and compare contents: identical → nothing to do, different → **conflict** |
| deleted | same | server copy → vault trash |
| same | deleted | local file → desktop trash |
| deleted/changed | changed/deleted | **conflict** |

- Every write is conditional: `If-Match` for updates and `If-None-Match: *` for new files. When two devices race, the loser gets HTTP 412 and the file becomes a conflict. No edit is ever silently lost.
- `s3vault-cli probe` checks that your provider enforces conditional writes.

### Encryption: per file, with the gpg CLI

```
password ──gpg S2K (iterated+salted, 65M, SHA-512)──► decrypts .s3vault/key.gpg ──► vault key (256-bit random)
vault key ──gpg --symmetric --s2k-mode 1 --cipher-algo AES256──► every <file>.gpg
```

**Performance and password changes**
- Files use the random vault key instead of the password. That makes per-file overhead ~4 ms instead of ~150 ms.
- Changing the password re-encrypts only `key.gpg`; no file is re-encrypted.

**What gpg is allowed to see**
- The passphrase reaches gpg only on file descriptor 3. It is never in argv, the environment or a file. `--no-symkey-cache` keeps gpg-agent from caching it.
- s3vault requires `DECRYPTION_OKAY` plus an integrity check (`GOODMDC` or AEAD) in gpg's status output. A tampered object, or a plain OpenPGP "literal" packet planted in place of a `.gpg` file, is rejected.
- Uploads are staged as ciphertext only. Downloads are written to a temp file next to the destination, checked, then renamed into place.

**Decrypting without s3vault**
```bash
gpg -d key.gpg                 # prints "s3vault-key-v1" and the vault key
gpg -d notes.md.gpg            # enter the vault key as the passphrase
```

**What the storage provider can still see**
- File and folder names, sizes and timestamps. This is by design, so the browser can list the vault without decrypting anything.
- A malicious server could swap two encrypted files of the same vault, or serve an older version. Per-file encryption without a signed index cannot detect that.

### No temporary plaintext

Previews, PDF rendering and editing all work in memory, and buffers are wiped when closed. The only way decrypted data reaches the disk is **Download**, to a place you choose, and sync into your tracked folders, which is the point of syncing.

## Build

```bash
./build.sh
```

**What `build.sh` does**
- Fetches pinned sources into `third_party/`: ImGui, GLFW, stb, pugixml, the SQLite amalgamation, curl headers and Font Awesome.
- If the X11/GL `-dev` headers are missing, fetches them without root, like gpu-hud does.
- Builds `build/s3vault`, `build/s3vault-cli` and the tests.

**Runtime libraries**
- libcurl and libsecret are loaded at runtime, so the build needs no `-dev` packages.
- The runtime needs `libcurl4`, `gnupg` ≥ 2.2, and optionally `poppler-utils` (PDF preview) and a Secret Service keyring. File and folder pickers are built in: external dialogs such as zenity open behind the window on GNOME.

Install to `~/.local`:
```bash
cmake --install build --prefix ~/.local
```

## Set up (Cloudflare R2 example)

1. Create a bucket and an R2 API token with **Object Read & Write** scoped to that bucket, in the Cloudflare dashboard under R2 → Manage API tokens. It gives you an access key ID and a secret.
2. Configure s3vault in one of two ways:
   - **GUI:** Settings → Storage, then **Save & reconnect**.
   - **CLI:**
     ```bash
     s3vault-cli config set storage.provider r2
     s3vault-cli config set storage.account_id <account id>
     s3vault-cli config set storage.bucket <bucket>
     s3vault-cli config set storage.access_key_id <key id>
     s3vault-cli secret set            # paste the secret; stored in the keychain
     s3vault-cli probe                 # auth, conditional writes, copy
     s3vault-cli init                  # choose the vault password
     s3vault-cli add-root ~/Documents --remote Documents
     s3vault-cli sync                  # or: s3vault-cli watch / the GUI
     ```

Other providers: set `storage.provider` to `aws`, `b2`, `wasabi`, `minio` or `custom`. Then set `storage.region`, plus `storage.endpoint` for MinIO/custom. `storage.addressing` (`path`/`virtual`) overrides the default.

Configuration lives in `~/.config/s3vault/config.ini` (secrets are never stored there). The index lives in `~/.local/share/s3vault/index.db`. `S3VAULT_HOME=<dir>` moves both, which is useful for several profiles.

## CLI

```
s3vault-cli --help
  config show|get|set · secret set · deps · probe [--multipart]
  init · passwd · lock · gen-password
  roots · add-root <dir> [--remote P] [--direction D] [--plain] · rm-root · pause · resume
  sync · watch
  ls [dir] [--sort name|type|size|modified] [--reverse] [-r]
  put <file> [vault-path] [--plain|--encrypt] [--overwrite] · get · cat · mkdir · mv · rm
  trash · restore <n> · purge [days]
  conflicts · resolve <id|all> keep-local|keep-remote|keep-both|keep-newest
```

## Tests

```bash
build/s3vault-tests            # unit tests: hashes, SigV4 reference vector, planner decision table, ignore rules,
                               # password strength, gpg round trip / wrong key / tamper / planted literal packet
tests/r2_integration.sh        # end-to-end against a real bucket, two simulated devices (see the header for test.env)
```

**What the integration test covers**
- the storage probe, including multipart
- vault init, and rejecting a second init or a wrong password
- sync in both directions, deletes going to the trash
- both-modified and modify/delete conflicts, and their resolution
- concurrent writers
- the CLI file operations
- tamper rejection, password change
- a 70 MiB multipart file, plain folders

**GUI smoke test**
- `s3vault --script "idle;expand:Docs;select:Docs/a.png;preview;idle;shot:/tmp/a.png;quit"` drives the UI without synthetic input and saves screenshots.
- Script windows are invisible, so tests never show up on your desktop. On exit, script mode prints the slowest UI frame. All network, crypto, listing and tree building runs on worker threads: syncing 360 MB kept every frame under 100 ms, and reconnecting or quitting mid-upload aborts transfers instead of waiting.

## Source layout

```
core/        portable engine (no UI): util, config, store (S3/SigV4), crypto (gpg), secret, index (SQLite),
             vault, sync (planner + engine), preview, edit
platform/    iface/platform.h + one backend per OS (linux implemented; macos, windows, ios, android reserved)
app/ui       ImGui panels shared by desktop builds;  app/desktop  GLFW main;  app/mobile  reserved (Flutter)
cli/         s3vault-cli
tests/       unit tests, R2 integration script, test helper
```

## Platforms

| Platform | Status | Plan |
|---|---|---|
| Linux | **done** | GLFW/GL3 + ImGui; inotify, libsecret, tmpfs |
| macOS | reserved | same UI; FSEvents, Keychain; gpg from GPGTools/Homebrew |
| Windows | reserved | same UI; ReadDirectoryChangesW, Credential Manager; Gpg4win |
| iOS / Android | reserved | Flutter UI over the C++ core (`dart:ffi`); RNP instead of the gpg CLI (same OpenPGP format) |

Font Awesome Free icons (SIL OFL 1.1 font, CC BY 4.0 icons) are fetched by `scripts/fetch-deps.sh`.
