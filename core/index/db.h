// Local state in SQLite: tracked roots, last-synced base per file, conflicts, remote listing cache.
#pragma once
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "store/s3_client.h"

struct sqlite3;

namespace s3v {

struct RootRow {
    int id = 0;
    std::string local_path;     // absolute
    std::string remote_prefix;  // logical dir in the vault ("" = vault root)
    std::string direction = "two-way";  // two-way | upload-only | download-only
    bool encrypt = true;        // default for new files
    bool paused = false;
};

struct FileRow {
    std::string rel;
    std::string remote_key;  // full object key at last sync
    std::string base_etag;   // remote ETag at last sync
    std::string base_hash;   // plaintext SHA-256 at last sync
    // Cached local stat → hash, to avoid rehashing unchanged files.
    uint64_t l_size = 0;
    int64_t l_mtime = 0;
    uint64_t l_inode = 0;
    std::string l_hash;
};

struct ConflictRow {
    int64_t id = 0;
    int root_id = 0;
    std::string rel;
    std::string kind;  // both-modified | both-added | local-deleted | remote-deleted
    bool local_exists = false;
    uint64_t local_size = 0;
    int64_t local_mtime = 0;  // unix seconds
    std::string local_hash;
    bool remote_exists = false;
    std::string remote_key, remote_etag;
    uint64_t remote_size = 0;
    int64_t remote_mtime = 0;
    int64_t detected = 0;
};

class Db {
public:
    ~Db();
    bool open(const std::string& path, std::string* error = nullptr);

    std::vector<RootRow> roots();
    int add_root(const RootRow& r);  // returns id, 0 on failure (e.g. duplicate path)
    bool update_root(const RootRow& r);
    void remove_root(int id);

    std::map<std::string, FileRow> files(int root_id);
    void upsert_file(int root_id, const FileRow& f);
    void delete_file(int root_id, const std::string& rel);

    std::vector<ConflictRow> conflicts(int root_id = 0);
    // Replaces all conflicts of a root with the given set (conflicts are re-derived on every sync).
    void set_conflicts(int root_id, const std::vector<ConflictRow>& rows);
    bool conflict(int64_t id, ConflictRow& out);
    void delete_conflict(int64_t id);

    void set_remote_cache(const std::vector<ObjectInfo>& objs, int64_t listed_at);
    std::vector<ObjectInfo> remote_cache(int64_t* listed_at = nullptr);

    std::string meta(const std::string& k);
    void set_meta(const std::string& k, const std::string& v);

private:
    bool exec(const char* sql);
    sqlite3* db_ = nullptr;
    std::recursive_mutex mu_;
};

}  // namespace s3v
