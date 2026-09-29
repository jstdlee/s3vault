# Windows backend (reserved)

Implement `platform/iface/platform.h` here:

- `fs_watcher_win.cpp`: ReadDirectoryChangesW (FILE_NOTIFY_CHANGE_FILE_NAME|DIR_NAME|SIZE|LAST_WRITE) per root;
  ERROR_NOTIFY_ENUM_DIR → overflow.
- `keychain_wincred.cpp`: Credential Manager (CredWriteW/CredReadW), or DPAPI-protected file.
- `session_tmp.cpp`: `%LOCALAPPDATA%\s3vault\tmp\<pid>` with a restrictive ACL; scrub before delete.
- `desktop.cpp`: ShellExecuteW, IFileOpenDialog, SHFileOperation (FOF_ALLOWUNDO) for the recycle bin.
- `core/util/subprocess.cpp` needs a CreateProcess variant (passphrase via an inherited pipe handle instead of fd 3;
  gpg accepts `--passphrase-fd <handle>` on Windows).

gpg: Gpg4win. libcurl: bundled DLL or vcpkg.
