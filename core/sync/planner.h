// Pure 3-way planner: (local, remote, last-synced base) → actions. No I/O, unit-tested.
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "index/db.h"

namespace s3v {

struct LocalFile {
    uint64_t size = 0;
    int64_t mtime_ns = 0;
    uint64_t inode = 0;
    std::string hash;  // plaintext SHA-256
};

struct RemoteFile {
    std::string key;
    std::string etag;
    uint64_t size = 0;
    int64_t mtime = 0;
    bool encrypted = false;
};

enum class ActKind {
    Upload,        // local → remote (conditional)
    Download,      // remote → local
    DeleteRemote,  // remote → vault trash
    DeleteLocal,   // local → desktop trash
    CheckEqual,    // both changed/added: compare contents before deciding
    ForgetBase,    // gone on both sides
    Conflict,
};

struct Action {
    ActKind kind;
    std::string rel;
    std::string key;            // remote key to write/read/delete
    std::string if_match;       // Upload: expected remote ETag
    bool if_none_match = false;  // Upload: remote must not exist
    std::string conflict_kind;  // Conflict / CheckEqual → kind if different
};

struct PlanInput {
    std::string direction = "two-way";  // two-way | upload-only | download-only
    bool default_encrypt = true;
    std::string remote_prefix;          // logical dir of the root ("" = vault root)
    std::string vault_prefix;           // "s3vault/main/"
    std::map<std::string, LocalFile> local;
    std::map<std::string, RemoteFile> remote;
    std::map<std::string, FileRow> base;
};

std::vector<Action> plan_sync(const PlanInput& in);

// The object key a new upload of `rel` should use.
std::string upload_key(const PlanInput& in, const std::string& rel, const RemoteFile* remote, const FileRow* base);

}  // namespace s3v
