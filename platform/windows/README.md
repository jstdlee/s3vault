# Windows backend

Implements `platform/iface/platform.h` with Win32:

- `fs_watcher_win.cpp`: ReadDirectoryChangesW per synced folder (recursive); a lost-event buffer means rescan.
- `keychain_wincred.cpp`: Credential Manager (generic credentials `s3vault:<account>`, DPAPI-protected, not roaming).
- `session_tmp.cpp`: `%LOCALAPPDATA%\s3vault\tmp\<pid>`; files are overwritten before delete (no tmpfs on Windows).
- `desktop.cpp`: recycle bin (SHFileOperation + FOF_ALLOWUNDO), IFileOpenDialog / IFileSaveDialog.
- `s3vault.manifest`: UTF-8 active code page (so narrow CRT file APIs take UTF-8 paths), per-monitor DPI awareness.
- Child processes: `core/util/subprocess_win.cpp` (CreateProcessW, inherited-handle allow-list). gpg gets the
  passphrase on an inherited pipe handle whose number is passed as `--passphrase-fd`.

Runtime: Gpg4win (or GnuPG for Windows) ≥ 2.2. libcurl and its DLLs ship next to the executables.
