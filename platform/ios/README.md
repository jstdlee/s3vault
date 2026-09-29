# iOS backend (reserved)

The mobile UI is Flutter (`app/mobile`), calling the C++ core through the C ABI (`core/include/s3vault/s3vault.h`,
to be added) with `dart:ffi`.

- No gpg CLI: add `core/crypto/rnp_backend.cpp` (RNP, BSD) producing/reading the same SKESK v4 + SEIPD AES-256
  messages; cross-tested against gpg in CI.
- Keychain Services for secrets; app-group container for the tmp dir (Data Protection class Complete).
- No background watching: sync on foreground + BGTaskScheduler; the Files app integration via a File Provider extension.
