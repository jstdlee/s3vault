// Built-in editing: a vault file is decrypted into memory, edited in the app's own text editor and saved
// straight back (encrypted again) with If-Match on the version that was opened. Plaintext never touches
// the disk and is never handed to another program.
#pragma once
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "config/config.h"
#include "vault/vault.h"

namespace s3v {

struct EditDoc {
    int id = 0;
    std::string logical;
    std::string key;
    std::string etag_at_open;  // server version the edits are based on
    std::string saved;         // text as last loaded/saved (to detect changes)
    std::string text;          // the editor buffer
    bool conflict = false;     // last save found a newer server version
    std::string error;
    bool dirty() const { return text != saved; }
};

class EditManager {
public:
    EditManager(Config& cfg, Vault& v) : cfg_(cfg), vault_(v) {}
    ~EditManager() { close_all(); }

    // Loads (and decrypts) into memory. Refuses non-UTF-8 content and files over the text limit.
    int open(const RemoteEntry& e, std::string& error);
    // The UI edits EditDoc::text in place through doc(); all calls happen on the UI thread except
    // save/reload, which take a snapshot and report back.
    EditDoc* doc(int id);
    std::vector<int> ids();
    bool any_dirty();

    // Upload `text` as the new version. Unless `force`, fails with precondition_failed if the server moved on.
    OpResult save(int id, const std::string& text, bool force = false);
    // Keep both: upload `text` as "name (conflict edited …).ext".
    OpResult save_as_copy(int id, const std::string& text);
    // Fetch the server's current version (discarding the buffer).
    OpResult reload(int id, std::string& text_out, std::string& etag_out);
    void apply_saved(int id, const std::string& text, const std::string& etag);  // after a successful save/reload
    void close(int id);  // wipes the buffers
    void close_all();

private:
    Config& cfg_;
    Vault& vault_;
    std::mutex mu_;
    std::map<int, EditDoc> docs_;
    int next_ = 1;
};

}  // namespace s3v
