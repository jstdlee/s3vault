#include "util/fs.h"

#include <dirent.h>

#include "util/compat.h"
#ifdef _WIN32
#include "util/secure.h"
#include "util/sha256.h"
#include "util/strings.h"
#include "util/win_text.h"
#else
#include <linux/magic.h>
#include <pwd.h>
#include <sys/statfs.h>
#endif

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "util/subprocess.h"

namespace s3v {

#ifdef _WIN32
FileStat stat_path(const std::string& path, bool follow_links) {
    FileStat r;
    WIN32_FILE_ATTRIBUTE_DATA d{};
    std::string p = path;
    if (p.size() == 2 && p[1] == ':') p += '/';  // "C:" alone means the drive's current directory
    if (!GetFileAttributesExW(to_wide(p).c_str(), GetFileExInfoStandard, &d)) return r;
    r.exists = true;
    r.is_link = !follow_links && (d.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);
    r.is_dir = !r.is_link && (d.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
    r.is_file = !r.is_link && !r.is_dir;
    r.size = (uint64_t(d.nFileSizeHigh) << 32) | d.nFileSizeLow;
    // FILETIME: 100 ns ticks since 1601-01-01.
    int64_t t = int64_t((uint64_t(d.ftLastWriteTime.dwHighDateTime) << 32) | d.ftLastWriteTime.dwLowDateTime);
    r.mtime_ns = (t - 116444736000000000LL) * 100;
    return r;
}

bool rename_replace(const std::string& from, const std::string& to) {
    return MoveFileExW(to_wide(from).c_str(), to_wide(to).c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED) != 0;
}

std::string real_path(const std::string& path) {
    wchar_t buf[32768];
    DWORD n = GetFullPathNameW(to_wide(path).c_str(), 32768, buf, nullptr);
    if (n == 0 || n >= 32768) return "";
    std::string r = slashes(from_wide(buf, int(n)));
    while (r.size() > 3 && r.back() == '/') r.pop_back();
    return stat_path(r, true).exists ? r : "";
}

static int make_dir(const char* p, mode_t) { return _mkdir(p); }
#else
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

bool rename_replace(const std::string& from, const std::string& to) { return ::rename(from.c_str(), to.c_str()) == 0; }

std::string real_path(const std::string& path) {
    char buf[PATH_MAX];
    return realpath(path.c_str(), buf) ? std::string(buf) : std::string();
}

static int make_dir(const char* p, mode_t mode) { return mkdir(p, mode); }
#endif

bool mkdirs(const std::string& path, mode_t mode) {
    if (path.empty()) return false;
    std::string cur;
    for (size_t i = 0; i <= path.size(); i++) {
        if (i == path.size() || (path[i] == '/' && i > 0)) {
            cur = path.substr(0, i);
            if (cur.size() == 2 && cur[1] == ':') continue;  // Windows drive
            if (make_dir(cur.c_str(), mode) != 0 && errno != EEXIST && !stat_path(cur, true).is_dir) return false;
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
#ifdef _WIN32
    std::string tmp;
    int fd = -1;
    for (int tries = 0; fd < 0 && tries < 20; tries++) {
        tmp = path + ".tmp-" + to_hex(random_bytes(4));
        fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, _S_IREAD | _S_IWRITE);
    }
    if (fd < 0) return false;
    (void)mode;  // NTFS ACLs: the file inherits its folder's permissions
#else
    std::string tmp = path + ".tmp-XXXXXX";
    int fd = mkostemp(tmp.data(), O_CLOEXEC);
    if (fd < 0) return false;
    fchmod(fd, mode);
#endif
    bool ok = write_all_fd(fd, data.data(), data.size()) && sync_fd(fd) == 0;
    close(fd);
    if (!ok || !rename_replace(tmp, path)) {
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
            sync_fd(fd);
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

#ifdef _WIN32
bool is_tmpfs(const std::string&) { return false; }

std::string home_dir() {
    if (const wchar_t* h = _wgetenv(L"USERPROFILE"); h && *h) return slashes(from_wide(h));
    return "C:/";
}
#else
bool is_tmpfs(const std::string& path) {
    struct statfs sf{};
    return statfs(path.c_str(), &sf) == 0 && sf.f_type == TMPFS_MAGIC;
}

std::string home_dir() {
    if (const char* h = getenv("HOME"); h && *h) return h;
    if (passwd* pw = getpwuid(getuid())) return pw->pw_dir;
    return "/tmp";
}
#endif

std::string display_path(const std::string& path) {
    std::string h = home_dir();
    if (h.size() > 1 && (path == h || (path.size() > h.size() && path.compare(0, h.size(), h) == 0 && path[h.size()] == '/')))
        return "~" + path.substr(h.size());
    return path;
}

bool copy_file(const std::string& from, const std::string& to) {
    std::string data;
    if (!read_file(from, data)) return false;
    return write_file_atomic(to, data, 0644);
}

}  // namespace s3v
