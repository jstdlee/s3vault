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
    std::string error;
    std::string etag;        // new remote ETag (uploads) or ETag read (downloads)
    std::string plain_hash;  // SHA-256 of the plaintext moved
    uint64_t plain_size = 0;
    static OpResult fail(std::string e) { OpResult r; r.error = std::move(e); return r; }
    static OpResult success() { OpResult r; r.ok = true; return r; }
};

using Progress = std::function<void(uint64_t done, uint64_t total)>;

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
    bool try_unlock_from_keychain();
    void lock();
    bool unlocked() { return keys_.unlocked(); }
    PassCache& keys() { return keys_; }
    Gpg& gpg() { return gpg_; }
    std::string vault_account() const;

    // ---- listing ----
    OpResult refresh(std::vector<RemoteEntry>* out = nullptr);
    std::vector<RemoteEntry> cached_entries();

    // ---- transfers (encrypt/decrypt by the key's .gpg suffix) ----
    OpResult upload_file(const std::string& local, const std::string& key, const Conditions& c,
                         const Progress& progress = {});
    // Writes to a temp file beside dest; `before_commit` may veto the final rename (return false).
    OpResult download_to(const std::string& key, const std::string& dest,
                         const std::function<bool()>& before_commit = {});
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
    OpResult need_key(SecureString& k);
    Config& cfg_;
    Db& db_;
    std::unique_ptr<S3Client> s3_;
    Gpg gpg_;
    PassCache keys_;
    std::string prefix_;
    bool has_key_ = false;
    std::mutex mu_;
};

}  // namespace s3v
