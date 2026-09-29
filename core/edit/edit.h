// Edit sessions: decrypt a vault file into the session tmp dir, open it in a text editor, notice real
// changes (content hash, not editor exit), and save back with If-Match on the version that was opened.
#pragma once
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "config/config.h"
#include "util/fs.h"
#include "vault/vault.h"

namespace s3v {

struct EditSession {
    int id = 0;
    std::string logical;
    std::string key;
    std::string etag_at_open;
    std::string hash_at_open;  // plaintext hash of the version that was opened (or last saved)
    std::string path;          // plaintext copy in the session tmp dir
    std::string current_hash;  // hash of the file as the editor left it
    bool changed = false;      // current_hash != hash_at_open
    bool prompt = false;       // changed since the user was last asked
    bool conflict = false;     // save-back found a newer server version
    std::string error;
    int64_t opened_at = 0;
    FileStat last_stat;
};

class EditManager {
public:
    EditManager(Config& cfg, Vault& v) : cfg_(cfg), vault_(v) {}
    ~EditManager() { close_all(); }

    // Downloads (decrypting if needed) and launches the editor. Returns the session id (0 on error).
    int open(const RemoteEntry& e, std::string& error, bool launch = true);
    // Detects content changes; sets `prompt` on sessions that changed since they were last shown.
    void poll();
    std::vector<EditSession> sessions();
    bool get(int id, EditSession& out);
    void clear_prompt(int id);
    bool relaunch(int id, std::string& error);

    // Upload the edited copy. Unless `force`, fails with precondition_failed when the server version moved on.
    OpResult save_back(int id, bool force = false);
    // Keep both: upload the edited copy as "name (conflict edited …).ext".
    OpResult save_as_copy(int id);
    // Throw away the local edits and reload the server's current version.
    OpResult reload(int id);
    void discard(int id);  // close and wipe
    void close_all();
    bool any_unsaved();

private:
    Config& cfg_;
    Vault& vault_;
    std::mutex mu_;
    std::map<int, EditSession> s_;
    int next_ = 1;
};

}  // namespace s3v
