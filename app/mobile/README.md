# Mobile app (reserved): Flutter

ImGui stays on desktop. The mobile app is Flutter (one UI code base for iOS and Android) calling the shared C++ core:

- `core/include/s3vault/s3vault.h`: a small C ABI over Vault/Engine/EditManager (opaque handles, JSON results).
- Dart bindings generated with `ffigen`; the core is built per ABI with CMake (Android NDK, iOS static xcframework).
- Crypto backend: RNP (no gpg CLI on phones); the file format is unchanged, so desktop and mobile read each other's files.
- Screens mirror the desktop: vault tree (sortable), on-tap preview (same size caps), in-app text editor with save-back
  prompt, grouped conflict review, settings with the same password lifecycle.
