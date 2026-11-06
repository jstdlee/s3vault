// A vault = one prefix in one bucket. Owns the S3 client, the vault key and the object-level operations.
//
// Layout under <prefix>/:
//   .s3vault/vault.json          format, id, creator (no secrets)
//   .s3vault/key.gpg             random vault key, gpg-encrypted with the user's password
//   .s3vault/trash/<ts>/<path>   soft-deleted objects
//   <path>                       plain file
//   <path>.gpg                   encrypted file (OpenPGP, passphrase = vault key)
//   <dir>/                       zero-byte folder marker (folders created in the UI)
#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "config/config.h"
#include "crypto/gpg.h"
#include "index/db.h"
#include "secret/passcache.h"
#include "store/s3_client.h"

namespace s3v {

struct RemoteEntry {
    std::string key;      // full object key
    std::string logical;  // path inside the vault, without .gpg ("docs/a.txt"; dirs without trailing '/')
    bool encrypted = false;
    bool dir_marker = false;
    uint64_t size = 0;
    std::string etag;
    int64_t mtime = 0;
};

struct TrashEntry {
    std::string key;       // trash object key
    std::string original;  // original full key
    std::string logical;
    bool encrypted = false;
    int64_t deleted_at = 0;
    uint64_t size = 0;
};

struct OpResult {
    bool ok = false;
    bool precondition_failed = false;  // remote changed since it was read
    bool bad_key = false;              // wrong password / vault key
    bool locked = false;               // vault key needed but locked
    bool too_large = false;
    bool rotating = false;             // a vault key replacement is unfinished (resume it with the new password)
    bool paused = false;               // key replacement stopped on request; it can be resumed
    std::string error;
    std::string etag;        // new remote ETag (uploads) or ETag read (downloads)
    std::string plain_hash;  // SHA-256 of the plaintext moved
    uint64_t plain_size = 0;
    static OpResult fail(std::string e) { OpResult r; r.error = std::move(e); return r; }
    static OpResult success() { OpResult r; r.ok = true; return r; }
};

using Progress = std::function<void(uint64_t done, uint64_t total)>;

// ---- vault key replacement ("rotation") ----
// For when the old key may be known to someone else (a leaked password plus an old key.gpg, or a leaked
// recovery key). A new random key replaces it and every encrypted object (vault and vault trash) is
// downloaded, decrypted and re-encrypted with the new key. Crash-safe: the new key is stored first in
// .s3vault/key-next.gpg (protected by the new password, together with the old key so the work can be
// resumed with the new password alone) and .s3vault/rotation.json marks the vault as "being rotated" so
// other devices drop the old key and stop writing with it. key.gpg is replaced only after every object
// was re-encrypted. Plain (unencrypted) files are not touched.
struct RotationStatus {
    bool active = false;  // .s3vault/rotation.json exists
    std::string device;   // who started it
    int64_t started = 0;
};

struct RotationStats {
    int files = 0;          // encrypted objects in the vault
    int trash_files = 0;    // encrypted objects in the vault trash
    int plain_files = 0;    // not encrypted: not touched
    uint64_t bytes = 0;     // encrypted bytes to download and upload again (vault + trash)
};

struct RotationProgress {
    int pass = 1;           // passes over the listing (later passes pick up objects changed meanwhile)
    int done = 0, total = 0;
    uint64_t bytes_done = 0, bytes_total = 0;
    int already_new = 0;    // objects already encrypted with the new key (resumed run)
    int unreadable = 0;     // objects neither key opens (left as they are)
    std::string current;    // logical path being processed
    bool finishing = false; // replacing key.gpg
};

class Vault {
public:
    Vault(Config& cfg, Db& db);
    ~Vault();

    // ---- connection ----
    // Secret from $S3VAULT_SECRET_KEY, else the keychain.
    bool connect(std::string& error);
    bool connected() const { return s3_ != nullptr; }
    S3Client& s3() { return *s3_; }
    static std::string secret_account(const StorageConfig& s);

    // ---- layout ----
    const std::string& prefix() const { return prefix_; }  // "s3vault/main/"
    std::string key_for(const std::string& logical, bool encrypted) const;
    bool parse_key(const std::string& key, RemoteEntry& e) const;  // false for internal/outside keys
    static std::string conflict_name(const std::string& logical, const std::string& tag);

    // ---- vault metadata & key ----
    // exists=false when there is no vault.json at the prefix.
    OpResult load_info(bool& exists);
    bool has_key() const { return has_key_; }
    OpResult init(const std::string& password);  // password may be empty (plain-only vault for now)
    OpResult set_password(const std::string& old_password, const std::string& new_password);
    OpResult unlock(const std::string& password);
    // Checks a password without the network (against the key.gpg fetched at unlock). Used to unlock the
    // UI while the key stays loaded for background sync. Falls back to unlock() if nothing is cached.
    OpResult verify_password(const std::string& password);
    // Key export. key_file(): the password-protected .s3vault/key.gpg (safe to store anywhere).
    // recovery_key(): the raw vault key after re-checking the password; anyone holding it can decrypt the vault.
    OpResult key_file(std::string& out);
    OpResult recovery_key(const std::string& password, SecureString& out);
    // GUI: keep the vault key loaded until quit/forget, so sync continues while the window is locked.
    void keep_key_for_session() { keys_.configure(keys_.mode(), 0); }
    bool try_unlock_from_keychain();
    void lock();
    bool unlocked() { return keys_.unlocked(); }

    // ---- key replacement (see RotationStatus above) ----
    static std::string new_vault_key();  // 64 hex characters; shown to the user as the new recovery key
    // Short, non-secret fingerprint of a vault key (stored as .s3vault/key-check; lets every device tell
    // whether the key it holds is still the vault's key).
    static std::string key_check_value(std::string_view key);
    OpResult rotation_status(RotationStatus& out);
    OpResult rotation_stats(RotationStats& out);
    // Starts a replacement: checks old_password against key.gpg, stores new_key (protected by
    // new_password) and re-encrypts everything. `cancel` pauses (result.paused); resume_rotation()
    // continues. The caller validates the new password's strength.
    OpResult rotate_key(const std::string& old_password, const std::string& new_password, const std::string& new_key,
                        const std::function<void(const RotationProgress&)>& progress = {},
                        const std::atomic<bool>* cancel = nullptr);
    OpResult resume_rotation(const std::string& new_password,
                             const std::function<void(const RotationProgress&)>& progress = {},
                             const std::atomic<bool>* cancel = nullptr);
    // A message once the loaded key was dropped because the vault key was replaced (or is being replaced)
    // on another device; "" otherwise. Reading clears it.
    std::string take_key_notice();
    PassCache& keys() { return keys_; }
    Gpg& gpg() { return gpg_; }
    std::string vault_account() const;

    // ---- listing ----
    OpResult refresh(std::vector<RemoteEntry>* out = nullptr);
    std::vector<RemoteEntry> cached_entries();

    // ---- transfers (encrypt/decrypt by the key's .gpg suffix) ----
    OpResult upload_file(const std::string& local, const std::string& key, const Conditions& c,
                         const Progress& progress = {});
    // In-memory upload (built-in editor): encrypted through gpg's pipes, never written to disk as plaintext.
    OpResult upload_bytes(const std::string& data, const std::string& key, const Conditions& c);
    // Writes to a temp file beside dest; `before_commit` may veto the final rename (return false).
    OpResult download_to(const std::string& key, const std::string& dest,
                         const std::function<bool()>& before_commit = {});
    // Raw object copy (no decryption), for "download everything as stored".
    OpResult download_raw(const std::string& key, const std::string& dest);
    OpResult download_to_memory(const std::string& key, std::string& out, size_t max);

    // ---- vault operations on logical paths ----
    OpResult mkdir(const std::string& logical_dir);
    // File or folder → trash.
    OpResult remove(const std::string& logical);
    // File or folder; fails if the destination exists.
    OpResult rename(const std::string& from_logical, const std::string& to_logical);
    std::vector<TrashEntry> trash_list(OpResult* err = nullptr);
    OpResult restore(const TrashEntry& t);
    OpResult purge_trash(int older_than_days, int* purged = nullptr);
    // Moves one object key into the trash (copy + delete). expected_etag guards against deleting a newer version.
    OpResult trash_key(const std::string& key, const std::string& expected_etag = "");

    // Temp dir for ciphertext staging (never plaintext).
    std::string staging_dir() const;

private:
    static const char* key_magic();  // first line of the decrypted key.gpg
    OpResult need_key(SecureString& k);
    // Drops the loaded key when the server says it is no longer (or soon no longer) the vault key.
    void guard_key(bool rotation_marker, const std::string& check_etag);
    bool key_is_current(std::string_view key, std::string* why);
    void drop_key(const std::string& why);
    OpResult run_rotation(const std::string& old_key, const std::string& new_key, const std::string& new_password,
                          const std::function<void(const RotationProgress&)>& progress, const std::atomic<bool>* cancel);
    OpResult rekey_object(const std::string& key, uint64_t size, const std::string& old_key, const std::string& new_key,
                          bool& already_new, bool& unreadable, bool& changed, std::string& old_etag, std::string& new_etag);
    Config& cfg_;
    Db& db_;
    std::unique_ptr<S3Client> s3_;
    Gpg gpg_;
    PassCache keys_;
    std::string prefix_;
    bool has_key_ = false;
    std::string key_ct_;  // key.gpg ciphertext from the last unlock (safe to hold: it is encrypted)
    std::atomic<bool> rotating_self_{false};  // this process is replacing the key: don't drop it
    std::string check_etag_;                  // ETag of .s3vault/key-check last confirmed to match our key
    std::string key_notice_;
    std::mutex mu_;
};

}  // namespace s3v
