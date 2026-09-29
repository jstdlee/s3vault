# macOS backend (reserved)

Implement `platform/iface/platform.h` here:

- `fs_watcher_fsevents.cpp`: FSEvents stream per root (kFSEventStreamCreateFlagFileEvents); report overflow on
  kFSEventStreamEventFlagMustScanSubDirs.
- `keychain_macos.cpp`: Security.framework (SecItemAdd/SecItemCopyMatching) with the same "<expires>:<secret>" value format.
- `session_tmp.cpp`: `$TMPDIR/s3vault/<pid>` (per-user, 0700); not RAM-backed, so `session_tmp_in_ram()` returns false and
  files are scrubbed before deletion.
- `desktop.cpp`: `open`, `open -t` for the editor, NSOpenPanel/`osascript` pickers, `NSFileManager trashItemAtURL`.

The UI (`app/ui`, `app/desktop`) builds unchanged with GLFW + OpenGL 3.3 core (macOS still ships GL 4.1).
gpg: GPGTools or `brew install gnupg`.
