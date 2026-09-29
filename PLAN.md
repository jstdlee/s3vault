# s3vault — plan (v3)

## Status (2026-09-29)

Phases 1 and 2 are done for Linux: the core engine, `s3vault-cli` and the ImGui desktop app. They are tested against a
real Cloudflare R2 bucket: 85 unit checks, plus a 43-check two-device integration script
(`tests/r2_integration.sh`). See README.md for usage.

Where the implementation differs from the text below:
- There is no zxcvbn. A built-in estimator checks length, character classes, repeats, common words and keyboard/alphabet
  runs, and requires a score of 3/4 or more.
- There is no libsodium. The key is held in memory with `mlock` + `explicit_bzero`, and random bytes come from
  `getrandom`. libcurl and libsecret are loaded at runtime (dlopen), and SQLite, pugixml and stb are vendored.
- Files encrypt with `--s2k-mode 1` because gpg ignores lower `--s2k-count` values for iterated S2K. `key.gpg` keeps
  mode 3 with 65M iterations.
- gpg's status output must include `DECRYPTION_OKAY` plus `GOODMDC`/AEAD. Otherwise a planted plain OpenPGP literal
  packet would decrypt "successfully".
- The desktop `--script` option drives the UI and saves screenshots, for smoke tests without synthetic input.

Next: phase 3 (hardening: crash/resume of large transfers, a trash purge schedule, fuzzing the preview loaders),
then phase 4 (macOS/Windows backends) and phase 5 (Flutter + RNP).


A sync client for **any S3-compatible object storage**: AWS S3, Cloudflare R2, MinIO, Backblaze B2, Wasabi and others. Its main job is to **sync files and move them safely between your own devices**. Encryption is optional, per root or per file, and uses standard OpenPGP files made by the existing `gpg` CLI.

- Desktop (Linux first, then macOS/Windows): C++17, CMake, Dear ImGui, GLFW/GL3. This is the same stack as gpu-hud.
- Mobile (iOS/Android): a **Flutter** UI over the same C++ core, through `dart:ffi` (§9).

## 1. Architecture

```
 app/desktop (ImGui)          app/mobile (Flutter)
        │  C++ API                 │  dart:ffi → C ABI (core/include/s3vault.h)
┌───────┴──────────────────────────┴──────────────────────────────────────┐
│ core/  sync engine · 3-way planner · transfer queue · conflict store     │
│        S3 client (SigV4, libcurl) + provider profiles + capability probe │
│        SQLite index (local state + cached remote metadata)               │
│        preview loaders (on demand, bounded) · edit sessions              │
│        secret store (password lifecycle) · config                        │
│        CryptoBackend ─┬─ GpgCli   (desktop: spawns gpg, pipes only)      │
│                       └─ Rnp      (mobile / no-gpg fallback; same format) │
└───────────────────────────────┬─────────────────────────────────────────┘
               platform/{linux,macos,windows,ios,android}
               fs watcher · keychain · tmp dir · open-with/editor · dialogs
```

## 2. Source layout

```
s3vault/
  CMakeLists.txt  build.sh  scripts/fetch-deps.sh
  core/
    include/s3vault/   api.hpp, s3vault.h (C ABI for Flutter)
    store/             sigv4, s3_client (GET/PUT/HEAD/LIST/COPY/DELETE, multipart, conditional),
                       providers (aws, r2, minio, b2, wasabi, custom), probe
    sync/              scanner, planner (3-way), transfer, conflict, ignore, engine
    crypto/            backend.h, gpg_cli, rnp (later), vault_key, hmac
    secret/            password cache (TTL, locked memory), strength check
    preview/           text, image (stb_image), pdf (pdftoppm); all bounded, on demand
    edit/              edit sessions: decrypt → editor → detect change → prompt → save back
    index/             SQLite schema + queries
    config/            config.ini, dependency discovery
  platform/  iface/ linux/ macos/ windows/ ios/ android/
  app/
    ui/                ImGui panels + icon font
    desktop/           GLFW + GL3 main
    mobile/            Flutter project (phase 5)
  cli/                 s3vault-cli
  tests/               unit, fake-S3 (with/without conditional writes), multi-device simulation
```

## 3. Storage backends (S3-compatible)

**Provider profiles** fill in sensible defaults, and every field can be overridden.

| profile | endpoint | region | addressing |
|---|---|---|---|
| aws | `s3.<region>.amazonaws.com` | user | virtual-host |
| r2 | `<account>.r2.cloudflarestorage.com` | `auto` | path |
| minio | user URL | `us-east-1` | path |
| b2 | `s3.<region>.backblazeb2.com` | user | virtual-host |
| wasabi | `s3.<region>.wasabisys.com` | user | virtual-host |
| custom | user | user | user |

**Capability probe** (setup and "Test" button). It writes to `.s3vault/probe/<dev>` and checks:
- `PUT If-None-Match: *` → 412 when the object already exists
- `PUT If-Match: <etag>` → 412 when the ETag is stale
- CopyObject with `x-amz-metadata-directive`
- multipart upload

AWS S3, R2 and MinIO support conditional PutObject.
If a provider fails the probe, s3vault falls back to **HEAD-before-PUT and verify-after-PUT**. The UI shows a warning that there is a small race window when two devices write the same file at the same moment. The multi-device tests cover this mode too.

Other compatibility rules:
- Multipart always uses equal part sizes except the last part. That is the strictest rule (R2's), so it satisfies every provider.
- Only SigV4 is used. No provider SDK is involved.

## 4. What is stored

One bucket, with one prefix per vault (for example `s3vault/<vault>/`):

```
.s3vault/vault.json          format version, vault id, created-by (no secrets)
.s3vault/key.gpg             random 256-bit vault key, gpg-encrypted with your password
.s3vault/devices/<dev>.json  device id → display name
.s3vault/trash/<ts>/<path>   soft-deleted objects (kept N days, then purged)
<path>                       plain file
<path>.gpg                   encrypted file (standard OpenPGP message)
```

**No custom metadata.** s3vault uses only what S3 already returns from LIST: key, size, ETag and LastModified. It never needs a per-file HEAD, and objects look like plain files to any other S3 tool.

- The remote version of a file is its **ETag**.
- The local version is the SHA-256 of the plaintext, kept in the SQLite index.
- For each path, the index stores `base` = {ETag, local hash} from the last successful sync.

## 5. Encryption — per file, with the gpg CLI

- **Password → vault key → files.** The password decrypts `key.gpg` (gpg S2K mode 3, 65M iterations). Files are encrypted with the random vault key using `--s2k-mode 1`.
- Measured on this box: about **3.7 ms per file** this way, compared with ~150 ms per file when the password is used directly (gpg ignores lower `--s2k-count` values). Bulk throughput is about 330 MB/s.
- A password change re-encrypts only `key.gpg`.
- Manual recovery needs only gpg: `gpg -d key.gpg`, then `gpg -d file.gpg` with that key.

```
gpg --batch --quiet --no-symkey-cache --pinentry-mode loopback --passphrase-fd 3
    --symmetric --cipher-algo AES256 --s2k-mode 1 --s2k-digest-algo SHA512 --set-filename ""
    [--compress-algo none   for already-compressed types]
    -o - -
```

- The passphrase only travels through fd 3. It never appears in argv or the environment and is never written to a file.
- Uploads and downloads stream through pipes. Downloads write `<dest>.s3v-tmp` and then `rename()` it into place.
- The output is standard OpenPGP (SKESK v4 + SEIPD, AES-256), so RNP and GopenPGP on mobile can read it.
- The password is checked against `key.gpg` on unlock, so a mistyped password can never encrypt new files.
- Encryption defaults are set per root. The manual-upload dialog can override them. Encrypted files are visible by their `.gpg` suffix and a lock badge.

## 6. Password lifecycle and strength

- **Creating a password:**
  - at least 14 characters
  - zxcvbn score ≥ 3
  - entered twice
  - a live strength meter
  - an optional diceware generator
- **How long it is remembered:** ask every time, until lock/exit, idle N minutes (default 15), or keychain for N days (libsecret, with an expiry stamp).
- **In memory:** only the vault key, in mlock'd memory. It is zeroed on timeout, lock or exit.
- **Actions:** lock now (menu + hotkey), change password, recovery info.

## 7. Sync and conflicts

A 3-way compare per file, plus conditional writes. **Local changed** means the local hash differs from base.hash. **Remote changed** means the ETag differs from base.etag.

| local vs base | remote vs base | action |
|---|---|---|
| same | same | nothing |
| changed | same | upload, `If-Match: <remote ETag>` |
| same | changed | download (atomic rename) |
| changed | changed | fetch the remote (decrypt if `.gpg`) and hash it. Same content → record the new base. Different → **conflict → manual** |
| deleted | same | remote → trash |
| same | deleted | local → OS trash |
| deleted/changed | changed/deleted | **conflict → manual** |
| new | new | same check: equal → record base, different → **conflict → manual** |

- **Why the fetch:** encrypted files differ in ciphertext even when the plaintext is the same, so equal content can only be confirmed by downloading. This only happens when both sides changed, which is rare, and it is subject to the preview size caps. Above the cap, it becomes a conflict without the check.
- If another device wins a race, the server answers 412. The path is then re-planned, so no write is ever lost.
- A rename is CopyObject + DeleteObject. It happens server side (no re-upload).
- **Remote changes:** LIST every 60 s (configurable) and on demand.
- **Local changes:** inotify (debounced), plus a rescan every 10 min and after `IN_Q_OVERFLOW`.

**Conflicts panel:**
- A tree grouped **root → parent dir → file**, with a checkbox at every level.
- Actions: **Keep both** (`name (conflict <device> <date>).ext`), **Overwrite remote**, **Overwrite local**, **Keep newest**, **Skip**.
- Each row shows size, mtime, device and a short hash for both sides.
- "Compare" opens both previews on demand (§8.2).
- Batch flow: select → action → review → apply. The apply step is still protected by If-Match.

## 8. Vault UI (desktop)

### 8.1 Vault tree
- An ImGui table with a tree column (`TreeNodeEx` inside `BeginTable`). Folders expand lazily from the SQLite cache.
- **Columns**, taken straight from S3 (all sortable, click again to reverse, folders always first):
  - Name
  - Type (from the extension)
  - Size (the object size; for `.gpg` files that is the encrypted size, within a few bytes of the original)
  - Last modified (S3 LastModified)
  - Status (local sync state)
- The columns you show and the sort order are saved.
- **Type icons** come from an embedded icon font (Font Awesome Free solid via IconFontCppHeaders; OFL/CC-BY, attributed in the README):
  - folder, text, code, image, pdf, audio, video, archive, document, other
  - **badges:** lock (encrypted), conflict, uploading/downloading, local-only, remote-only
- Filter box (name glob) plus a type filter.
- Multi-select with Ctrl/Shift.
- **CRUD** (context menu and toolbar): new folder, upload file(s) (picker or drag and drop), download to…, rename, move, delete → trash, restore from trash, copy path.

### 8.2 Preview: only when clicked, always bounded
- **Nothing is fetched or decrypted automatically.**
  - Selecting a row shows metadata only, from the cache.
  - Content loads only after **Preview** is clicked (button, Space or double-click).
  - There is no prefetch and no thumbnails in the tree.
- **One preview at a time.** Opening another preview, closing the pane, locking, or timing out (default 2 min idle) frees it immediately:
  - plaintext buffers are overwritten with `sodium_memzero`, then freed
  - GL textures are deleted
  - PDF page PNGs are unlinked
- **Hard caps.** They are checked before anything is downloaded, using the object size from LIST, and again while streaming:
  - the gpg/HTTP reader stops and kills gpg once the byte cap is passed
  - the UI then shows "too large to preview — Download / Open externally"

| type | cap (default, configurable) | how it is rendered | extra guards |
|---|---|---|---|
| text / code | 2 MB, 50k lines | UTF-8 check → monospace view with line numbers; invalid UTF-8 is shown as a hex dump | wraps long lines, shows only visible lines (`ImGuiListClipper`) |
| image (png/jpg/gif/bmp/tga/psd) | 50 MB file, 64 MP decoded | `stbi_info` checks the dimensions first (decompression-bomb guard), then decodes, uploads to a texture and frees the pixel buffer | fit/zoom; GIF shows the first frame |
| pdf | 100 MB | `pdftoppm -png -r ≤150 -f N -l N`, one page at a time, when requested | 10 s timeout per page, 8 MP max per page; the file sits in the tmpfs session dir only while the preview is open |

- A preview never writes plaintext to disk, except for the PDF, which goes to tmpfs (RAM).

### 8.3 Edit in a text editor (with save-back)
- **Edit** / **Force open in text editor** is in the context menu. "Force" opens any type, including unknown or binary files, after a warning about binary content and size.
- **Steps:**
  1. Decrypt (or download) to `$XDG_RUNTIME_DIR/s3vault/<pid>/edit/<id>/<name>`, mode 0600. Record the ETag and plaintext hash at the moment it was opened.
  2. Launch `editor` from the config:
     - `auto` means `$VISUAL`, then `$EDITOR`, then the `xdg-mime` default for `text/plain`
     - terminal editors run through `terminal = x-terminal-emulator -e`
  3. Watch the file with inotify (`IN_CLOSE_WRITE`, `IN_MOVED_TO`, because many editors save by rename). Ignore saves that leave the content hash unchanged.
- **Save-back prompt:**
  - **When:** on the first real change. The **Open edits** list (with a badge on the file) lets you finish later. GUI editors often return straight away, so s3vault does not rely on the editor process exiting.
  - **Wording:** "`notes.md` was changed in the editor. Save it back to the vault?"
  - **Buttons:** **[Save back]** **[Keep editing]** **[Discard changes]**
- **Save back** re-encrypts if needed and uploads with `If-Match: <ETag at open>`.
  - If the remote changed in the meantime, it becomes a conflict prompt: **Keep both / Overwrite remote / Reopen with the remote version**.
  - If the file is inside a tracked local root, the local copy is updated too.
- Closing the edit session (Done / Discard / app exit) wipes the temp file. On exit with unsaved changes, s3vault asks once: **Save all / Discard all / Cancel exit**.

### 8.4 Temporary plaintext
- Location: `$XDG_RUNTIME_DIR/s3vault/<pid>/{preview,edit,open}/`, mode 0700. That is tmpfs, so it lives in RAM. The fallback is `~/.cache/s3vault/tmp`, where files are overwritten before they are unlinked.
- It is wiped on exit (normal, SIGINT, SIGTERM, SIGHUP), lock and password expiry. On startup, the dirs of dead PIDs are removed.
- External apps can keep their own copies. This is noted next to "Open externally" and "Edit".

## 9. Mobile: Flutter + the shared C++ core

- **Code sharing:** Flutter UI, with `dart:ffi` calling the C++ core. The sync logic, S3 client and planner are written once.
- **Crypto:** the RNP `CryptoBackend` reads and writes the same OpenPGP format. A gpg↔RNP cross-check test runs in CI.
- **Background:** BGTaskScheduler (iOS) and WorkManager (Android), plus a sync when the app comes to the foreground. There is no live watching.
- **UI:** the same features — sortable tree, previews on tap (with the same caps), edit via the in-app text editor.

## 10. Configuration

`~/.config/s3vault/config.ini` contains no secrets:

```ini
[deps]
gpg = auto                 ; version ≥ 2.2 checked at startup
pdftoppm = auto            ; optional; disables PDF preview if missing
opener = xdg-open
editor = auto              ; $VISUAL → $EDITOR → xdg-mime text/plain default
terminal = x-terminal-emulator -e
[storage]
provider = r2              ; aws | r2 | minio | b2 | wasabi | custom
endpoint = auto
region = auto
addressing = auto          ; path | virtual
bucket = ...
prefix = s3vault/main
access_key_id = ...        ; secret in keychain (libsecret) or S3VAULT_SECRET_KEY
[security]
remember = idle            ; ask | session | idle | keychain
idle_minutes = 15
keychain_days = 7
min_length = 14
[preview]
text_max_mb = 2
image_max_mb = 50
image_max_mpix = 64
pdf_max_mb = 100
pdf_dpi = 110
idle_free_seconds = 120
[sync]
poll_seconds = 60
rescan_minutes = 10
concurrency = 8
bandwidth_kbps = 0
trash_days = 30
[ui]
columns = name,type,size,modified,status
sort = name:asc
```

Settings → **Dependencies / Storage** shows found/missing, the path and version of each tool, and the capability probe results, with a Test button for each.

## 11. Phases

1. **Core + CLI (Linux):**
   - S3 client with provider profiles, capability probe, conditional writes and multipart
   - gpg backend
   - vault create/unlock
   - SQLite index
   - 3-way planner and conflict store
   - `s3vault-cli`: `init`, `unlock`, `add-root`, `sync`, `ls --sort`, `put`, `get`, `mv`, `rm`, `conflicts`, `resolve`, `edit`
   - Tests: fake S3 (with and without conditional writes), a 3-device random-edit simulation that checks no edit is ever lost, and a MinIO container for integration.
2. **Linux GUI:**
   - vault tree with icons and sortable columns, and CRUD
   - on-demand bounded previews
   - edit sessions with the save-back prompt
   - conflicts panel
   - transfers, settings/deps/probe
   - password lifecycle, inotify, tmp cleanup
3. **Hardening:** integration tests against real R2 and AWS S3 scratch buckets, crash/resume, trash purge, large multipart, bandwidth limits, and fuzzing the preview loaders.
4. **macOS + Windows desktop:** FSEvents / ReadDirectoryChangesW, Keychain / Credential Manager, and gpg from GPGTools / Gpg4win.
5. **Mobile (Flutter):** C ABI, the RNP backend, the app, background sync.
