// Per-process directory for decrypted plaintext: $XDG_RUNTIME_DIR (tmpfs) when available.
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>

#include "platform.h"
#include "util/fs.h"

namespace s3v::platform {

static std::string base_dir() {
    const char* x = getenv("XDG_RUNTIME_DIR");
    if (x && *x && stat_path(x, true).is_dir) return std::string(x) + "/s3vault";
    return home_dir() + "/.cache/s3vault/tmp";
}

static std::string& session_dir_storage() {
    static std::string d;
    return d;
}

std::string session_tmp_dir() {
    static std::mutex mu;
    std::lock_guard<std::mutex> lk(mu);
    std::string& d = session_dir_storage();
    if (d.empty()) {
        std::string b = base_dir();
        mkdirs(b, 0700);
        chmod(b.c_str(), 0700);
        d = b + "/" + std::to_string(getpid());
    }
    if (!stat_path(d, true).is_dir) {
        mkdirs(d, 0700);
        chmod(d.c_str(), 0700);
    }
    return d;
}

bool session_tmp_in_ram() { return is_tmpfs(base_dir()); }

void wipe_session_tmp() {
    std::string d = base_dir() + "/" + std::to_string(getpid());
    remove_tree(d, !is_tmpfs(base_dir()));
}

int cleanup_stale_tmp() {
    std::string b = base_dir();
    int n = 0;
    DIR* dir = opendir(b.c_str());
    if (!dir) return 0;
    bool scrub = !is_tmpfs(b);
    while (dirent* e = readdir(dir)) {
        char* end = nullptr;
        long pid = strtol(e->d_name, &end, 10);
        if (!end || *end || pid <= 0 || pid == getpid()) continue;
        // Alive and ours? Leave it alone (another s3vault instance).
        if (kill(pid_t(pid), 0) == 0) {
            std::string exe;
            char buf[4096];
            ssize_t k = readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), buf, sizeof buf - 1);
            if (k > 0) exe.assign(buf, size_t(k));
            if (exe.find("s3vault") != std::string::npos) continue;
        }
        remove_tree(b + "/" + e->d_name, scrub);
        n++;
    }
    closedir(dir);
    return n;
}

static std::function<void()>* g_extra = nullptr;

static void on_signal(int sig) {
    // Not strictly async-signal-safe, but we are exiting anyway and the wipe matters more.
    if (g_extra && *g_extra) (*g_extra)();
    wipe_session_tmp();
    signal(sig, SIG_DFL);
    raise(sig);
}

void install_exit_cleanup(std::function<void()> extra) {
    static std::function<void()> keep;
    keep = std::move(extra);
    g_extra = &keep;
    signal(SIGPIPE, SIG_IGN);
    for (int s : {SIGINT, SIGTERM, SIGHUP}) signal(s, on_signal);
    atexit([] { wipe_session_tmp(); });
}

}  // namespace s3v::platform
