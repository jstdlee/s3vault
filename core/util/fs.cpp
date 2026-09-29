#include "util/fs.h"

#include <dirent.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "util/subprocess.h"

namespace s3v {

FileStat stat_path(const std::string& path, bool follow_links) {
    FileStat r;
    struct stat st{};
    if ((follow_links ? stat(path.c_str(), &st) : lstat(path.c_str(), &st)) != 0) return r;
    r.exists = true;
    r.is_dir = S_ISDIR(st.st_mode);
    r.is_file = S_ISREG(st.st_mode);
    r.is_link = S_ISLNK(st.st_mode);
    r.size = uint64_t(st.st_size);
    r.mtime_ns = int64_t(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
    r.inode = uint64_t(st.st_ino);
    return r;
}

bool mkdirs(const std::string& path, mode_t mode) {
    if (path.empty()) return false;
    std::string cur;
    for (size_t i = 0; i <= path.size(); i++) {
        if (i == path.size() || (path[i] == '/' && i > 0)) {
            cur = path.substr(0, i);
            if (mkdir(cur.c_str(), mode) != 0 && errno != EEXIST) return false;
        }
    }
    return stat_path(path, true).is_dir;
}

bool read_file(const std::string& path, std::string& out, size_t max) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    out.clear();
    bool ok = read_all_fd(fd, out, max);
    close(fd);
    return ok;
}

bool write_file_atomic(const std::string& path, const std::string& data, mode_t mode) {
    std::string tmp = path + ".tmp-XXXXXX";
    int fd = mkostemp(tmp.data(), O_CLOEXEC);
    if (fd < 0) return false;
    fchmod(fd, mode);
    bool ok = write_all_fd(fd, data.data(), data.size()) && fsync(fd) == 0;
    close(fd);
    if (!ok || rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

void secure_unlink(const std::string& path) {
    int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) {
        struct stat st{};
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
            static const char zeros[65536] = {};
            off_t left = st.st_size;
            while (left > 0) {
                size_t n = size_t(left < off_t(sizeof zeros) ? left : off_t(sizeof zeros));
                if (!write_all_fd(fd, zeros, n)) break;
                left -= off_t(n);
            }
            fsync(fd);
        }
        close(fd);
    }
    unlink(path.c_str());
}

void remove_tree(const std::string& path, bool scrub) {
    FileStat st = stat_path(path);
    if (!st.exists) return;
    if (!st.is_dir) {
        if (scrub && st.is_file) secure_unlink(path);
        else unlink(path.c_str());
        return;
    }
    if (DIR* d = opendir(path.c_str())) {
        while (dirent* e = readdir(d)) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            remove_tree(path + "/" + e->d_name, scrub);
        }
        closedir(d);
    }
    rmdir(path.c_str());
}

bool is_tmpfs(const std::string& path) {
    struct statfs sf{};
    return statfs(path.c_str(), &sf) == 0 && sf.f_type == TMPFS_MAGIC;
}

std::string home_dir() {
    if (const char* h = getenv("HOME"); h && *h) return h;
    if (passwd* pw = getpwuid(getuid())) return pw->pw_dir;
    return "/tmp";
}

bool copy_file(const std::string& from, const std::string& to) {
    std::string data;
    if (!read_file(from, data)) return false;
    return write_file_atomic(to, data, 0644);
}

}  // namespace s3v
