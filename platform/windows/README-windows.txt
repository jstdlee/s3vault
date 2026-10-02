s3vault for Windows
===================

Run s3vault.exe (desktop app) or s3vault-cli.exe (command line). Keep the DLL files next to them.

Needs GnuPG for the encryption: install Gpg4win from https://gpg4win.org (the default options are fine).
The gpg that comes with Git for Windows does not work with s3vault.

Settings:          %APPDATA%\s3vault\config.ini
Index and cache:   %LOCALAPPDATA%\s3vault
Remembered secrets: Windows Credential Manager, entries named "s3vault:..."
Decrypted previews never touch the disk; files you open for editing are kept in memory.

The build is not code-signed yet: on first start SmartScreen may say "Windows protected your PC";
choose More info, then Run anyway.
