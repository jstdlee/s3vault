// Filesystem helpers.
#pragma once
#include <sys/types.h>

#include <cstdint>
#include <string>

namespace s3v {

struct FileStat {
    bool exists = false;
    bool is_dir = false;
    bool is_file = false;
    bool is_link = false;
    uint64_t size = 0;
    int64_t mtime_ns = 0;
    uint64_t inode = 0;
};

FileStat stat_path(const std::string& path, bool follow_links = false);
bool mkdirs(const std::string& path, mode_t mode = 0755);
bool read_file(const std::string& path, std::string& out, size_t max = size_t(-1));
// Writes to path.tmp-XXXX then renames over path.
bool write_file_atomic(const std::string& path, const std::string& data, mode_t mode = 0644);
// Overwrites the file with zeros before unlinking (for plaintext left outside tmpfs).
void secure_unlink(const std::string& path);
// Recursively deletes a directory (files overwritten first when `scrub`).
void remove_tree(const std::string& path, bool scrub = false);
bool is_tmpfs(const std::string& path);
std::string home_dir();
// "/home/me/Documents" → "~/Documents" (for display only).
std::string display_path(const std::string& path);
bool copy_file(const std::string& from, const std::string& to);

}  // namespace s3v
