// Platform services the core and UI need. Implemented per OS under platform/<os>/.
#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "util/secure.h"

namespace s3v::platform {

// ---- What to tell the user (names and install hints differ per OS) ----
const char* keychain_name();     // "Secret Service (libsecret)", "Windows Credential Manager"
const char* install_gpg_hint();  // "Install gnupg", "Install Gpg4win"
const char* install_pdf_hint();  // how to get pdftoppm

// ---- Secrets (libsecret / Keychain / Credential Manager / Keystore) ----
bool keychain_available();
// Loads libsecret/glib and does one lookup so their one-time initialisation happens on the calling thread.
// Call from main() before starting other threads or creating a GL context.
void keychain_preload();
// expires_unix 0 = no expiry.
bool keychain_store(const std::string& account, std::string_view secret, int64_t expires_unix = 0);
// False if missing or expired (an expired entry is deleted).
bool keychain_load(const std::string& account, SecureString& out);
bool keychain_erase(const std::string& account);

// ---- Session temp dir for decrypted plaintext (tmpfs where possible) ----
// "$XDG_RUNTIME_DIR/s3vault/<pid>" (created 0700 on first call).
std::string session_tmp_dir();
bool session_tmp_in_ram();
// Deletes the whole session dir (scrubbing files when not on tmpfs).
void wipe_session_tmp();
// Removes dirs left by dead processes (crash). Returns how many were removed.
int cleanup_stale_tmp();
// Installs SIGINT/SIGTERM/SIGHUP handlers that wipe the session dir before exiting.
void install_exit_cleanup(std::function<void()> extra = {});

// ---- Desktop integration ----
// (No "open with"/external editor on purpose: decrypted content is only viewed/edited inside s3vault.)
// Move a local file to the desktop trash. False if not possible (caller may fall back to delete).
bool trash_local(const std::string& path);
// Blocking native dialogs (run from a worker thread). Empty on cancel.
std::vector<std::string> pick_files(const std::string& title, bool multiple);
std::string pick_folder(const std::string& title);
std::string pick_save_path(const std::string& title, const std::string& suggested_name);

// ---- File watching ----
class FsWatcher {
public:
    struct Event {
        int root_id;
        std::string rel_path;
    };
    FsWatcher();
    ~FsWatcher();
    bool add_root(int root_id, const std::string& path);
    void remove_root(int root_id);
    // Collects events for up to timeout_ms. `overflow` set when events were lost (rescan needed).
    std::vector<Event> poll(int timeout_ms, bool& overflow);

private:
    struct Impl;
    Impl* impl_;
};

}  // namespace s3v::platform
