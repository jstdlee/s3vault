// Recursive inotify watcher. Overflow (or any doubt) is reported so the engine rescans.
#include <dirent.h>
#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

#include <cstring>
#include <map>
#include <mutex>
#include <string>

#include "platform.h"
#include "util/fs.h"

namespace s3v::platform {

struct FsWatcher::Impl {
    int fd = -1;
    std::mutex mu;
    struct W {
        int root_id;
        std::string rel;  // directory relative to root ("" = root)
    };
    std::map<int, W> wds;
    std::map<int, std::string> roots;  // root_id → absolute path

    void add_dir(int root_id, const std::string& abs, const std::string& rel) {
        uint32_t mask = IN_CLOSE_WRITE | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE_SELF |
                        IN_ATTRIB | IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK;
        int wd = inotify_add_watch(fd, abs.c_str(), mask);
        if (wd < 0) return;
        wds[wd] = {root_id, rel};
        DIR* d = opendir(abs.c_str());
        if (!d) return;
        while (dirent* e = readdir(d)) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            if (e->d_type == DT_DIR || (e->d_type == DT_UNKNOWN && stat_path(abs + "/" + e->d_name).is_dir))
                add_dir(root_id, abs + "/" + e->d_name, rel.empty() ? e->d_name : rel + "/" + e->d_name);
        }
        closedir(d);
    }
};

FsWatcher::FsWatcher() : impl_(new Impl) { impl_->fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC); }

FsWatcher::~FsWatcher() {
    if (impl_->fd >= 0) close(impl_->fd);
    delete impl_;
}

bool FsWatcher::add_root(int root_id, const std::string& path) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    if (impl_->fd < 0) return false;
    impl_->roots[root_id] = path;
    impl_->add_dir(root_id, path, "");
    return true;
}

void FsWatcher::remove_root(int root_id) {
    std::lock_guard<std::mutex> lk(impl_->mu);
    for (auto it = impl_->wds.begin(); it != impl_->wds.end();) {
        if (it->second.root_id == root_id) {
            inotify_rm_watch(impl_->fd, it->first);
            it = impl_->wds.erase(it);
        } else {
            ++it;
        }
    }
    impl_->roots.erase(root_id);
}

std::vector<FsWatcher::Event> FsWatcher::poll(int timeout_ms, bool& overflow) {
    overflow = false;
    std::vector<Event> out;
    if (impl_->fd < 0) {
        overflow = true;
        return out;
    }
    pollfd p{impl_->fd, POLLIN, 0};
    if (::poll(&p, 1, timeout_ms) <= 0) return out;
    alignas(inotify_event) char buf[64 * 1024];
    std::lock_guard<std::mutex> lk(impl_->mu);
    for (;;) {
        ssize_t n = read(impl_->fd, buf, sizeof buf);
        if (n <= 0) break;
        for (char* q = buf; q < buf + n;) {
            auto* ev = reinterpret_cast<inotify_event*>(q);
            q += sizeof(inotify_event) + ev->len;
            if (ev->mask & IN_Q_OVERFLOW) { overflow = true; continue; }
            auto it = impl_->wds.find(ev->wd);
            if (it == impl_->wds.end()) continue;
            if (ev->mask & IN_IGNORED) { impl_->wds.erase(it); continue; }
            Impl::W w = it->second;
            std::string name = ev->len ? ev->name : "";
            std::string rel = w.rel.empty() ? name : (name.empty() ? w.rel : w.rel + "/" + name);
            if ((ev->mask & IN_ISDIR) && (ev->mask & (IN_CREATE | IN_MOVED_TO))) {
                auto r = impl_->roots.find(w.root_id);
                if (r != impl_->roots.end()) impl_->add_dir(w.root_id, r->second + "/" + rel, rel);
                overflow = true;  // new subtree: files inside may predate the watch → rescan
            }
            out.push_back({w.root_id, rel});
        }
    }
    return out;
}

}  // namespace s3v::platform
