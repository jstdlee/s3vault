// Recursive ReadDirectoryChangesW watcher, one thread per synced folder. A lost-event buffer
// (ERROR_NOTIFY_ENUM_DIR or a zero-length result) is reported as overflow so the engine rescans.
#include <windows.h>

#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "platform.h"
#include "util/win_text.h"

namespace s3v::platform {

struct FsWatcher::Impl {
    struct Root {
        HANDLE dir = INVALID_HANDLE_VALUE;
        HANDLE stop = nullptr;
        std::string path;
        std::thread th;
    };
    std::mutex mu;
    std::condition_variable cv;
    std::vector<Event> events;
    bool overflow = false;
    std::map<int, std::unique_ptr<Root>> roots;

    void run(int root_id, Root* r) {
        alignas(DWORD) char buf[64 * 1024];
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        const DWORD filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE |
                             FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_ATTRIBUTES;
        for (;;) {
            ResetEvent(ov.hEvent);
            if (!ReadDirectoryChangesW(r->dir, buf, sizeof buf, TRUE, filter, nullptr, &ov, nullptr)) {
                std::lock_guard<std::mutex> lk(mu);
                overflow = true;
                cv.notify_all();
                break;
            }
            HANDLE wait[2] = {ov.hEvent, r->stop};
            if (WaitForMultipleObjects(2, wait, FALSE, INFINITE) != WAIT_OBJECT_0) {
                CancelIoEx(r->dir, &ov);
                DWORD ignored = 0;
                GetOverlappedResult(r->dir, &ov, &ignored, TRUE);
                break;
            }
            DWORD n = 0;
            bool ok = GetOverlappedResult(r->dir, &ov, &n, FALSE);
            std::lock_guard<std::mutex> lk(mu);
            if (!ok || n == 0) {  // buffer overflowed: changes were lost
                overflow = true;
            } else {
                for (char* p = buf;;) {
                    auto* fi = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(p);
                    std::string rel = slashes(from_wide(fi->FileName, int(fi->FileNameLength / sizeof(wchar_t))));
                    if (fi->Action == FILE_ACTION_ADDED || fi->Action == FILE_ACTION_RENAMED_NEW_NAME) {
                        // A folder moved in arrives with files already inside it: rescan to be safe.
                        DWORD a = GetFileAttributesW(to_wide(r->path + "/" + rel).c_str());
                        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) overflow = true;
                    }
                    events.push_back({root_id, rel});
                    if (!fi->NextEntryOffset) break;
                    p += fi->NextEntryOffset;
                }
            }
            cv.notify_all();
        }
        CloseHandle(ov.hEvent);
    }
};

FsWatcher::FsWatcher() : impl_(new Impl) {}

FsWatcher::~FsWatcher() {
    std::vector<int> ids;
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        for (auto& [id, r] : impl_->roots) ids.push_back(id);
    }
    for (int id : ids) remove_root(id);
    delete impl_;
}

bool FsWatcher::add_root(int root_id, const std::string& path) {
    remove_root(root_id);
    HANDLE d = CreateFileW(to_wide(path).c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
    if (d == INVALID_HANDLE_VALUE) return false;
    auto r = std::make_unique<Impl::Root>();
    r->dir = d;
    r->path = path;
    r->stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Impl::Root* raw = r.get();
    std::lock_guard<std::mutex> lk(impl_->mu);
    impl_->roots[root_id] = std::move(r);
    raw->th = std::thread([this, root_id, raw] { impl_->run(root_id, raw); });
    return true;
}

void FsWatcher::remove_root(int root_id) {
    std::unique_ptr<Impl::Root> r;
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        auto it = impl_->roots.find(root_id);
        if (it == impl_->roots.end()) return;
        r = std::move(it->second);
        impl_->roots.erase(it);
    }
    SetEvent(r->stop);
    if (r->th.joinable()) r->th.join();
    CloseHandle(r->dir);
    CloseHandle(r->stop);
}

std::vector<FsWatcher::Event> FsWatcher::poll(int timeout_ms, bool& overflow) {
    std::unique_lock<std::mutex> lk(impl_->mu);
    impl_->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] { return !impl_->events.empty() || impl_->overflow; });
    overflow = impl_->overflow;
    impl_->overflow = false;
    std::vector<Event> out;
    out.swap(impl_->events);
    return out;
}

}  // namespace s3v::platform
