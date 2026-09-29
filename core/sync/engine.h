// Sync engine: scan → plan → execute (parallel) → record conflicts. Also resolves conflicts and runs
// the background loop (file watcher + remote polling) for the GUI.
#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "config/config.h"
#include "index/db.h"
#include "sync/planner.h"
#include "vault/vault.h"

namespace s3v {

namespace platform { class FsWatcher; }

enum class Resolution { KeepLocal, KeepRemote, KeepBoth, KeepNewest };
const char* resolution_name(Resolution r);

struct SyncReport {
    int uploaded = 0, downloaded = 0, deleted_remote = 0, deleted_local = 0, conflicts = 0, errors = 0;
    int unchanged = 0;
    bool locked_skipped = false;  // encrypted files skipped because the vault is locked
    bool retry_soon = false;      // files were still being written; look again in a few seconds
    std::vector<std::string> messages;
    std::string summary() const;
};

struct Transfer {
    std::string what;  // "upload", "download", "compare"
    std::string path;
    uint64_t done = 0, total = 0;
    bool queued = false;  // waiting for its turn
};

class Engine {
public:
    Engine(Config& cfg, Db& db, Vault& vault);
    ~Engine();

    // ---- roots ----
    // Returns the new root id, 0 on error.
    int add_root(const std::string& local_path, const std::string& remote_prefix, const std::string& direction,
                 bool encrypt, std::string& error);

    // ---- one-shot sync (CLI, tests, and the background loop) ----
    SyncReport sync_all(bool refresh_remote = true);

    // ---- conflicts ----
    OpResult resolve(int64_t conflict_id, Resolution r);

    // ---- background loop (GUI) ----
    void start();
    void stop();
    void request_sync();  // as soon as possible
    bool running() const { return running_; }
    bool syncing() const { return syncing_; }
    int64_t last_sync() const { return last_sync_; }
    std::string last_summary();
    std::vector<Transfer> transfers();
    std::vector<std::string> log_lines(size_t max = 200);
    void log(const std::string& line);
    // Transfers shown in the UI (also used for manual uploads/downloads started from the UI).
    int transfer_begin(const std::string& what, const std::string& path, uint64_t total, bool queued = false);
    void transfer_start(int id);
    void transfer_progress(int id, uint64_t done, uint64_t total);
    void transfer_end(int id);
    // Called (from the engine thread) after each sync pass.
    std::function<void()> on_synced;

private:
    SyncReport sync_root(const RootRow& root, const std::vector<RemoteEntry>& remote);
    void scan(const RootRow& root, std::map<std::string, FileRow>& base, std::map<std::string, LocalFile>& out,
              SyncReport& rep);
    void run_actions(const RootRow& root, const PlanInput& in, std::vector<Action>& acts, SyncReport& rep,
                     std::vector<ConflictRow>& conflicts);
    void exec_one(const RootRow& root, const PlanInput& in, const Action& a, SyncReport& rep,
                  std::vector<ConflictRow>& conflicts, std::mutex& mu);
    ConflictRow make_conflict(const RootRow& root, const PlanInput& in, const std::string& rel, const std::string& kind);
    bool local_unchanged(const std::string& abs, const LocalFile* planned);
    void loop();

    Config& cfg_;
    Db& db_;
    Vault& vault_;
    std::mutex sync_mu_;  // one sync/resolve at a time

    std::atomic<bool> running_{false}, syncing_{false}, stop_{false}, want_sync_{false}, want_rescan_{false}, watches_ready_{false};
    std::atomic<int64_t> last_sync_{0};
    std::thread thread_, watch_thread_;
    std::mutex wake_mu_;
    std::condition_variable wake_;
    platform::FsWatcher* watcher_ = nullptr;

    std::mutex info_mu_;
    std::map<int, Transfer> transfers_;
    int next_transfer_ = 1;
    std::deque<std::string> log_;
    std::string last_summary_;
};

}  // namespace s3v
