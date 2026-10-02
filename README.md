# s3vault

[![build and release](https://github.com/jstdlee/s3vault/actions/workflows/build-release.yml/badge.svg)](https://github.com/jstdlee/s3vault/actions/workflows/build-release.yml)
[![release](https://img.shields.io/github/v/release/jstdlee/s3vault?include_prereleases&sort=semver)](https://github.com/jstdlee/s3vault/releases)
[![license: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

Sync, browse and encrypt your files on **any S3-compatible storage**: Cloudflare R2, AWS S3, MinIO, Backblaze B2, Wasabi and others.

- **Encryption:** each file can be encrypted with standard OpenPGP, using the `gpg` you already have.
- **Built-in viewing and editing:** everything happens inside the app, so decrypted content is never written to disk and never handed to another program.
- **Conflicts:** they are never resolved silently. You review them grouped by folder and apply one decision to many files at once.

Desktop app for Linux and Windows (C++17 · Dear ImGui · GLFW · OpenGL 3.3) plus a headless `s3vault-cli`. macOS, iOS and Android are on the [roadmap](#roadmap).

![s3vault: sidebar with synced folders, Finder-style file list and the inspector with a Quick Look preview](docs/screenshots/01-files.png)

## Contents

[Features](#features) · [Gallery](#gallery) · [How sync works](#how-sync-works) · [Security](#security) ·
[Build](#build) · [Set up](#set-up-cloudflare-r2-example) · [CLI](#cli) · [Tests](#tests) · [Source layout](#source-layout) ·
[Roadmap](#roadmap) · [License](#license)

## Features

```mermaid
mindmap
  root((s3vault))
    Storage
      Any S3-compatible service
        Cloudflare R2
        AWS S3
        MinIO · B2 · Wasabi
      Capability probe
      No custom metadata
    Sync
      Tracked folders
        two-way
        upload-only backup
        download-only mirror
      inotify watcher and polling
      3-way compare
      Conditional writes
      Vault trash and restore
    Conflicts
      Grouped by folder
      Keep both
      Overwrite server or local
      Keep newest
      Side-by-side compare
    Security
      OpenPGP via gpg CLI
      Password-protected vault key
      Recovery key export
      Lock hides the UI, sync continues
      No plaintext temp files
    Vault browser
      Sortable tree with icons
      Tracked-folder icon and status
      Upload queue with progress
      Rename · move · delete
      Download all, decrypted or as stored
    Built-in tools
      Text · image · PDF preview
      Text editor with save-back
      File and folder picker
```

- **Tracked folders.** Keep a local folder in sync with a vault folder:
  - Modes: **two-way**, **upload-only** (backup: local deletions and server-only files are never pulled down), or **download-only** (mirror).
  - Changes are picked up by inotify, with a periodic rescan as a safety net, and the server is polled every 60 s.
  - A `.s3vaultignore` file (gitignore syntax) excludes files.
- **Vault browser.**
  - A folder tree with type icons, sortable by name, type, size, last modified and status. Filter by name or type.
  - A green sync icon marks tracked folders and their files. Hovering shows the local path and direction, and every status explains itself.
  - Finder model: you are always *in* a folder (breadcrumb + back/forward), and new folders and uploads go there. Click a selected row again, click empty space, or press Esc to deselect.
- **File operations.**
  - Upload with the built-in file browser (multi-select, folders included) or by drag and drop.
  - Uploads show as a **queue with progress** in Transfers, and every result is logged.
  - New folder (with an editable parent folder), **rename / move** (server-side copy, nothing re-uploaded), and **delete** to the vault trash, then restore.
  - Buttons in the details pane, plus F2 and Delete keys.
- **Download all.** One click copies the whole vault to a new dated folder:
  - **decrypted:** plain files, or
  - **as stored:** encrypted `.gpg` files plus `.s3vault/key.gpg`, so the copy stays protected and opens later with your password.
- **Built-in viewer and editor.**
  - Previews for text/code, images (png/jpg/gif/bmp/tga/psd) and PDF (page by page; poppler reads it from a pipe).
  - A text editor (Editor tab, Ctrl+S) that saves back to the vault.
  - Everything stays in memory, and there is no "open with".
- **Password, lock and keys.**
  - New passwords need at least 14 characters and must pass a strength check; there is a generator.
  - **Lock**, manually or after N idle minutes, hides the window. The vault key stays loaded, so **sync keeps running**.
  - **Forget vault key** stops encrypted sync.
  - **Export** the password-protected key file, or the raw recovery key.
- **Mac-style interface.**
  - **No system title bar.** The top strip drags the window, a double-click maximizes it, and every edge resizes.
    Minimize, maximize and close sit at the top right.
  - **Utility cluster** at the top right of every view: search (Ctrl+P), tasks and activity log (Ctrl+J, with a
    progress ring and a count while files move), help (F1) and settings (Ctrl+,).
  - **Find any feature (Ctrl+P).** Type a few letters of a view, an action, a setting or a term, in English or your
    language. A setting is scrolled into view and briefly highlighted.
  - A sidebar with All Files, Trash, your synced folders (live status dots), **Sync a folder** (the one highlighted
    feature), Transfers, Conflicts and Editor (badges). Drag its edge to resize it (double-click resets); Ctrl+B hides it.
  - A toolbar with back/forward, a clickable path, search, upload, new folder and the inspector toggle.
  - An inspector with Quick Look, information and actions; its edge resizes too.
  - Sheets for every dialog; drag them anywhere and they reopen there. A three-step setup assistant and a lock screen.
  - **Help (F1)** with Concepts, a Glossary and every keyboard shortcut, searchable.
  - **Four looks:** System, Light, Dark and Tokyo Night (Ctrl+Shift+T switches).
  - **Four languages:** English, 简体中文, 日本語 and 한국어, switched at once in Settings; the CJK font follows the
    language. File names are never translated.
  - **Motion with a purpose:** the segment pill and the sidebar selection slide (160 ms), sheets and toasts fade in
    (200 ms). Settings › Motion → Reduced (or the desktop's setting) keeps the fades and drops the sliding.
  - Keyboard: Ctrl+P find · F1 help · Ctrl+J tasks · Space Quick Look · Enter/F2 rename · Delete move to Trash ·
    Ctrl+E edit · Ctrl+U upload · Ctrl+Shift+N new folder · Ctrl+Shift+A sync a folder · Ctrl+F search ·
    Ctrl+I inspector · Ctrl+B sidebar · Ctrl+= / − / 0 text size · Alt+←/→ back/forward · Backspace enclosing folder.
- **Robust UI.**
  - Network, crypto and tree building run on worker threads; syncing hundreds of MB keeps every frame under 100 ms.
  - If the GPU driver can't open a window (e.g. an LLM is using all unified memory), s3vault restarts itself with software rendering.

## Gallery

Every screen below is the current build. Dark and light follow your desktop setting; Tokyo Night and the language are in Settings › Appearance.

| | |
|---|---|
| ![Tokyo Night](docs/screenshots/18-tokyo-night.png) **Tokyo Night**, the frameless window with the utility cluster at the top right and **Sync a folder** highlighted. | ![Palette](docs/screenshots/19-palette-ja.png) **Find any feature (Ctrl+P)**, here in 日本語, with each command's shortcut. |
| ![Help](docs/screenshots/20-help-zh.png) **Help (F1)** in 简体中文: concepts, glossary and shortcuts. | ![Shortcuts](docs/screenshots/21-shortcuts.png) **Keyboard shortcuts**, from the same list the palette uses. |
| ![Settings Korean](docs/screenshots/22-settings-ko.png) **Settings** in 한국어: language, theme, text size and motion. | |
| ![Files](docs/screenshots/01-files.png) **Files.** Sidebar with synced folders and status dots, a Finder-style list, and the inspector with Quick Look. | ![Light](docs/screenshots/13-light-files.png) **Light appearance.** A text file previewed in the inspector (monospaced, from memory). |
| ![PDF](docs/screenshots/02-pdf-preview.png) **PDF Quick Look**, page by page, from memory. | ![Editor](docs/screenshots/03-editor.png) **Built-in editor.** Ctrl+S saves back with If-Match. |
| ![Conflicts](docs/screenshots/04-conflicts.png) **Conflicts** grouped by folder; one decision for many files. | ![Compare](docs/screenshots/05-compare.png) **Compare** this device's version with the server's. |
| ![Transfers](docs/screenshots/06-transfers.png) **Transfers.** The upload queue with progress and the activity log; the tasks button at the top right shows the overall progress ring. | ![Trash](docs/screenshots/11-trash.png) **Trash.** Put Back, or Empty Trash. |
| ![Settings](docs/screenshots/08-settings.png) **Settings.** Cards that save as you change them. | ![Settings light](docs/screenshots/14-light-settings.png) **Settings, light.** |
| ![Export key](docs/screenshots/09-export-key.png) **Export Key** sheet: backup key file or recovery key. | ![File browser](docs/screenshots/10-file-browser.png) **Built-in file browser** for uploads and synced folders. |
| ![Setup](docs/screenshots/12-setup.png) **Setup assistant, step 1:** connect your storage. | ![Create vault](docs/screenshots/16-create-vault.png) **Step 2:** create the vault password, with a strength meter. |
| ![Unlock](docs/screenshots/07-unlock.png) **Unlock** at start, or browse names only without the key. | ![Locked](docs/screenshots/15-locked.png) **Locked window.** Content is hidden while sync keeps running. |
| ![Windows](docs/screenshots/17-windows-setup.png) **Windows.** The same app on Windows (captured by CI on a Windows runner). | |

## How sync works

### Why not a CRDT

A CRDT merges concurrent edits automatically, which fits structured data (text documents, JSON). Files in a vault are opaque, and most are encrypted, so there is nothing meaningful to merge.

s3vault therefore uses a **per-file 3-way compare** plus the storage service's own **compare-and-swap** (conditional writes). The result has the same property you want from a CRDT, *no edit is ever lost*, but anything that can't be merged safely is surfaced as a conflict for you to decide.

For every file, the local index remembers a **base**: the server's ETag and the plaintext SHA-256 from the last successful sync. Each pass compares **local**, **server** and **base**:

```mermaid
flowchart TD
    S([sync pass for one file]) --> B{base exists?}
    B -- no --> N{exists where?}
    N -- local only --> U1[upload with If-None-Match: *]
    N -- server only --> D1[download → temp file → atomic rename]
    N -- both --> CE[download + compare contents]
    B -- yes --> L{local changed?<br/>hash ≠ base}
    L -- no --> R{server changed?<br/>ETag ≠ base}
    R -- no --> OK([nothing to do])
    R -- yes --> D2[download]
    L -- yes --> R2{server changed?}
    R2 -- no --> U2["upload with If-Match: base ETag"]
    R2 -- yes --> CE
    CE -- same bytes --> REC([record new base])
    CE -- different --> C([conflict → Conflicts tab])
    L -- deleted --> DL{server changed?}
    DL -- no --> T1[server copy → vault trash]
    DL -- yes --> C
    R -- deleted --> DR{local changed?}
    DR -- no --> T2[local file → desktop trash]
    DR -- yes --> C
```

The direction of a tracked folder filters these actions:
- **upload-only** never downloads, and never deletes on the server because of a local deletion.
- **download-only** never uploads.

### Single sync pass

```mermaid
sequenceDiagram
    participant W as inotify / 60 s poll
    participant E as Sync engine (worker threads)
    participant I as Local index (SQLite)
    participant S as S3 / R2
    W->>E: change detected (debounced 2.5 s)
    E->>S: ListObjectsV2 (key, size, ETag, LastModified)
    E->>I: load base rows
    E->>E: scan folder (rehash only files whose size/mtime/inode changed)
    E->>E: plan: upload / download / trash / compare / conflict
    par up to N files at once
        E->>S: PUT with If-Match / If-None-Match (encrypted by gpg first)
        E->>S: GET → gpg decrypt → temp file → rename
    end
    E->>I: new base per file, conflict list
```

### Overwrite protection: conflict interception

Two devices edit the same file at the same moment. Both saw ETag `e1`, and each uploads with `If-Match: e1`. The storage accepts exactly one:

```mermaid
sequenceDiagram
    participant A as Laptop
    participant S as Storage
    participant B as Desktop
    A->>S: PUT notes.md.gpg If-Match: "e1"
    S-->>A: 200 OK, ETag "e2"
    B->>S: PUT notes.md.gpg If-Match: "e1"
    S-->>B: 412 Precondition Failed (someone else wrote first)
    Note over B: nothing overwritten. Next pass: server changed AND local changed
    B->>S: GET notes.md.gpg (e2), decrypt, compare with local
    Note over B: contents differ → conflict, shown in the Conflicts tab
```

In the **Conflicts** tab you pick a resolution for one file or a whole folder. Every resolution is again a conditional write, so a third concurrent change is caught as well:

```mermaid
flowchart LR
    C([conflict]) --> KB[Keep both]
    C --> OS[Overwrite server]
    C --> OL[Overwrite local]
    C --> KN[Keep newest]
    KB --> KB1["server copy → 'name (conflict remote …)' (server-side copy + download)<br/>then local → original name, If-Match"]
    OS --> OS1["upload local with If-Match: current ETag<br/>(deleted locally → server copy to vault trash)"]
    OL --> OL1["old local file → desktop trash<br/>download the server version"]
    KN --> KN1{newer side?}
    KN1 -- local --> OS
    KN1 -- server --> OL
```

The built-in editor uses the same rule. Saving uploads with `If-Match` on the version you opened. If someone changed the file meanwhile, you choose **Keep both / Overwrite server / Reload server version**.

## Security

### Keys and passwords

```mermaid
flowchart TD
    P[Your password] -- "gpg S2K: iterated + salted, 65M rounds, SHA-512" --> KG[".s3vault/key.gpg<br/>(stored in the bucket)"]
    KG -- decrypts to --> VK["Vault key<br/>256-bit random, made once when the vault is created"]
    VK -- "gpg --symmetric AES-256 (salted S2K)" --> F1[notes.md.gpg]
    VK --> F2[photo.png.gpg]
    VK --> F3[…every encrypted file]
    VK -. "Export → recovery key" .-> RK["Recovery key<br/>(the raw vault key)"]
    KG -. "Export → backup key file" .-> BK["key.gpg copy<br/>(still needs the password)"]
```

**Encryption with gpg**
- Every encrypted file is a standard OpenPGP message (SKESK v4 + SEIPD, AES-256) produced by your installed `gpg`.
- It is not a custom format. You can always decrypt without s3vault:
  ```bash
  gpg -d key.gpg              # enter your password → prints "s3vault-key-v1" and the vault key
  gpg -d notes.md.gpg         # enter the vault key as the passphrase
  ```
- The passphrase reaches gpg only through file descriptor 3. It is never on the command line, in the environment or in a file, and `--no-symkey-cache` keeps gpg-agent from caching it.
- s3vault accepts a decryption only if gpg reports `DECRYPTION_OKAY` plus an integrity check (`GOODMDC` or AEAD). A tampered object, or an unencrypted OpenPGP "literal" packet planted in place of a `.gpg` file, is rejected.

**Password and vault key**
- Your password protects only `key.gpg`, with slow, deliberate key stretching.
- Files are encrypted with the random vault key inside it. That makes per-file overhead ~4 ms instead of ~150 ms.
- **Changing the password re-encrypts only `key.gpg`**; no file is touched. The vault key, and so the recovery key, stays the same.
- New passwords need at least 14 characters and must pass a strength check (character classes, repeats, common words, keyboard/alphabet runs). The generator makes about 120-bit passwords.
- The unlocked vault key lives only in locked (non-swappable) memory and is wiped on quit or **Forget vault key**.
- **Lock** hides the window behind the password screen but keeps the key loaded, so background sync of encrypted files continues. Unlocking checks the password offline against the cached `key.gpg`.
- Remember options: lock the window after N idle minutes (default, 15), keep until quit, keychain for N days, or ask every time. "Ask every time" means no background sync of encrypted files.

**Backup key file vs recovery key** (Settings → Keys & backup)

| | Backup key file | Recovery key |
|---|---|---|
| What it is | a copy of `key.gpg` | the raw vault key |
| Protected by | your password | nothing: whoever has it can decrypt every file |
| Use it when | the server copy of `key.gpg` is lost or damaged | you forgot the password |
| Changes when the password changes | yes (export again) | no |
| Keep it | anywhere | offline: a password manager or printed |

Exporting the recovery key asks for the password again, and the file is written with mode 600.

**What the storage provider sees**
- File and folder names, sizes, timestamps and the ciphertext. Names are visible by design, so the vault can be listed without the key.
- A malicious provider could swap two encrypted files of the same vault, or serve an older version. Per-file encryption without a signed index cannot detect that. Integrity of each file *is* checked.
- The S3 secret key is stored in the desktop keychain (libsecret), or read from `S3VAULT_SECRET_KEY`. It never goes in `config.ini`.

**No plaintext left behind**
- Previews, PDF rendering and the editor work in memory, and their buffers are wiped when closed.
- Decrypted data reaches your disk only through what you ask for: **Download**, **Download all (decrypted)**, and syncing into your tracked folders.
- Tracked-folder downloads go to a temp file next to the target and are renamed into place only after decryption and integrity checks succeed.

## Download

Prebuilt binaries are on the [Releases](https://github.com/jstdlee/s3vault/releases) page:

| File | System |
|---|---|
| `s3vault-*-linux-x86_64.tar.gz` | Linux, Intel/AMD 64-bit |
| `s3vault-*-linux-arm64.tar.gz` | Linux, ARM 64-bit |
| `s3vault-*-windows-x86_64.zip` | Windows 10/11, 64-bit |

- **Versioned releases** come from `v*` tags.
- **Nightly** is rebuilt on every push to `main`. The [build and release](.github/workflows/build-release.yml) workflow
  compiles on all three systems, runs the unit tests on each (on Windows: native gpg, Credential Manager and a
  GUI frame), packages and publishes.

**Linux**
```bash
tar xzf s3vault-*-linux-$(uname -m | sed 's/aarch64/arm64/').tar.gz
cd s3vault-*/ && ./bin/s3vault          # GUI;  ./bin/s3vault-cli --help
```

**Windows**
- Unzip and run `s3vault.exe` (or `s3vault-cli.exe`). Keep the DLLs next to them; they are libcurl and its TLS libraries.
- Install [Gpg4win](https://gpg4win.org) for encryption. The gpg bundled with Git for Windows does not work: it cannot
  receive the passphrase on a Windows pipe handle.
- Settings live in `%APPDATA%\s3vault`, the index in `%LOCALAPPDATA%\s3vault`, and remembered secrets in the Windows
  Credential Manager.
- The build is not code-signed yet, so SmartScreen may warn on first start: choose *More info → Run anyway*.

## Build

```bash
./build.sh
```

**What `build.sh` does**
- Fetches pinned sources into `third_party/`: ImGui, GLFW, stb, pugixml, the SQLite amalgamation, curl headers and Font Awesome.
- If the X11/GL `-dev` headers are missing, fetches them without root.
- Builds `build/s3vault`, `build/s3vault-cli` and the tests.

**Runtime**
- libcurl and libsecret are loaded at runtime, so the build needs no `-dev` packages.
- Needs `libcurl4`, `gnupg` ≥ 2.2, and optionally `poppler-utils` (PDF preview) and a Secret Service keyring.
- `--software` forces CPU rendering.

Install to `~/.local`:
```bash
cmake --install build --prefix ~/.local
```

**Windows build:** with [MSYS2](https://www.msys2.org) (UCRT64 shell), the same as CI:
```bash
pacman -S git python mingw-w64-ucrt-x86_64-{gcc,cmake,ninja,curl,gnupg}
scripts/fetch-deps.sh && cmake -S . -B build -G Ninja && cmake --build build
```
Or cross-compile from Linux with MinGW-w64 (`g++-mingw-w64-x86-64-posix`):
`cmake -S . -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake`.

## Set up (Cloudflare R2 example)

1. Create a bucket and an R2 API token with **Object Read & Write** scoped to that bucket, in the Cloudflare dashboard under R2 → Manage API tokens.
2. In the app, open **Settings → Storage**: provider `r2`, account ID, bucket, access key ID and secret. Then **Save & reconnect**, and s3vault offers to create the vault. Or use the CLI:
   ```bash
   s3vault-cli config set storage.provider r2
   s3vault-cli config set storage.account_id <account id>
   s3vault-cli config set storage.bucket <bucket>
   s3vault-cli config set storage.access_key_id <key id>
   s3vault-cli secret set            # paste the secret; stored in the keychain
   s3vault-cli probe                 # auth, conditional writes, copy, multipart
   s3vault-cli init                  # choose the vault password
   s3vault-cli add-root ~/Documents --remote Documents
   s3vault-cli sync                  # or: s3vault-cli watch / the GUI
   ```

**Other providers:** set `storage.provider` to `aws`, `b2`, `wasabi`, `minio` or `custom`, plus `storage.region`, and `storage.endpoint` for MinIO or custom. `storage.addressing` (`path` or `virtual`) overrides the default.

**Where things are stored**
- Configuration: `~/.config/s3vault/config.ini` (never contains secrets).
- Index: `~/.local/share/s3vault/index.db`.
- `S3VAULT_HOME=<dir>` moves both.

## CLI

```
s3vault-cli --help
  config show|get|set · secret set · deps · probe [--multipart]
  init · passwd · lock · gen-password · export-key <file> [--recovery]
  roots · add-root <dir> [--remote P] [--direction D] [--plain] · rm-root · pause · resume
  sync · watch
  ls [dir] [--sort name|type|size|modified] [--reverse] [-r]
  put <file> [vault-path] [--plain|--encrypt] [--overwrite] · get · cat · mkdir · mv · rm
  trash · restore <n> · purge [days]
  conflicts · resolve <id|all> keep-local|keep-remote|keep-both|keep-newest
```

## Tests

```bash
build/s3vault-tests            # unit tests: SHA-256/HMAC, SigV4 reference vector, planner decision table,
                               # ignore rules, password strength, gpg round trip / wrong key / tamper / planted packet,
                               # portability (atomic replace, binary pipes, UTF-8 names, argv quoting, keychain)
tests/r2_integration.sh        # end to end against a real bucket, two simulated devices (see its header for test.env)
```

**What the integration test covers**
- the storage probe, including multipart
- vault init and wrong-password rejection
- sync in both directions, deletes going to the trash
- both-modified and modify/delete conflicts, and their resolution
- concurrent writers
- CLI file operations
- tamper rejection and password change
- a 70 MiB multipart file, plain folders

**GUI smoke tests**
```bash
s3vault --software --script "sleep:3;unlock;idle;expand:Docs;select:Docs/a.png;preview;idle;shot:a.png;quit"
```
- Script runs use an invisible window.
- On exit, they report the slowest UI frame.

## Source layout

```
core/        portable engine, no UI: util, config, store (S3/SigV4), crypto (gpg), secret, index (SQLite),
             vault, sync (planner + engine), preview, edit (in-memory documents)
platform/    iface/platform.h + one backend per OS (linux and windows implemented; macos, ios, android reserved)
app/ui       ImGui panels shared by desktop builds;  app/desktop  GLFW main;  app/mobile  reserved (Flutter)
app/ui/i18n  strings.py (English → 中文 / 日本語 / 한국어) and gen.py, which writes i18n_table.inc
cli/         s3vault-cli
tests/       unit tests, R2 integration script, test helper
docs/        screenshots
```

## Roadmap

```mermaid
timeline
    title s3vault platforms
    Linux (done) : sync engine, CLI, ImGui desktop
                 : gpg encryption, built-in viewer and editor
                 : conflict review, lock with background sync
    Windows (done) : same ImGui UI, one zip
                   : ReadDirectoryChangesW, Credential Manager
                   : Gpg4win, CreateProcess passphrase pipe
    macOS : same ImGui UI (GLFW + GL 4.1)
          : FSEvents watcher, Keychain
          : gpg from GPGTools or Homebrew
    Android : Flutter UI over the C++ core (dart ffi, NDK)
            : RNP instead of the gpg CLI, same file format
            : Keystore, Storage Access Framework, WorkManager
    iOS : Flutter UI over the C++ core (static xcframework)
        : RNP, Keychain, File Provider extension
        : BGTaskScheduler background sync
```

| Platform | Status | UI | Watch / background | Secrets | Crypto |
|---|---|---|---|---|---|
| Linux | ✅ done | ImGui + GLFW/GL3 | inotify + polling | libsecret | gpg CLI |
| macOS | planned | same ImGui code | FSEvents | Keychain | gpg (GPGTools/Homebrew) |
| Windows | ✅ done | same ImGui code | ReadDirectoryChangesW | Credential Manager | gpg CLI (Gpg4win) |
| Android | planned | Flutter over the C++ core (`dart:ffi`) | WorkManager, SAF folders | Android Keystore | RNP (OpenPGP library) |
| iOS | planned | Flutter over the C++ core | BGTaskScheduler, File Provider | Keychain | RNP |

**Shared across platforms**
- **File format:** all platforms read and write the same OpenPGP files, so a vault created on Linux opens on a phone.
- **Planned per-platform work:** each `platform/<os>/README.md` lists what that port needs.
- **Mobile note:** phones have no gpg command, so the mobile apps will use RNP, which reads and writes the same files. A gpg ↔ RNP cross-test will be part of CI.

## License

s3vault is free software under the **GNU General Public License v3.0** (see [LICENSE](LICENSE)).

Third-party components keep their own licenses:
- Dear ImGui, GLFW, pugixml, stb and SQLite: MIT, zlib, MIT, public domain/MIT and public domain respectively.
- Font Awesome Free: SIL OFL 1.1 font, CC BY 4.0 icons.

These are fetched by `scripts/fetch-deps.sh` and not stored in this repository.
