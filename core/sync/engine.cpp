#include "sync/engine.h"

#include <dirent.h>
#include "util/compat.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>

#include "platform.h"
#include "sync/ignore.h"
#include "util/fs.h"
#include "util/sha256.h"
#include "util/strings.h"

namespace s3v {

static const size_t kCompareMax = 64u << 20;  // CheckEqual downloads at most this much plaintext

const char* resolution_name(Resolution r) {
    switch (r) {
        case Resolution::KeepLocal: return "keep-local";
        case Resolution::KeepRemote: return "keep-remote";
        case Resolution::KeepBoth: return "keep-both";
        case Resolution::KeepNewest: return "keep-newest";
    }
    return "?";
}

std::string SyncReport::summary() const {
    char b[256];
    snprintf(b, sizeof b, "%d up, %d down, %d deleted remote, %d deleted local, %d conflicts, %d errors%s", uploaded,
             downloaded, deleted_remote, deleted_local, conflicts, errors,
             locked_skipped ? " (some encrypted files skipped: vault locked)" : "");
    return b;
}

Engine::Engine(Config& cfg, Db& db, Vault& vault) : cfg_(cfg), db_(db), vault_(vault) {}

Engine::~Engine() { stop(); }

void Engine::log(const std::string& line) {
    std::lock_guard<std::mutex> lk(info_mu_);
    time_t t = time(nullptr);
    struct tm tmv {};
    localtime_r(&t, &tmv);
    char ts[16];
    strftime(ts, sizeof ts, "%H:%M:%S", &tmv);
    log_.push_back(std::string(ts) + "  " + line);
    while (log_.size() > 1000) log_.pop_front();
}

std::vector<std::string> Engine::log_lines(size_t max) {
    std::lock_guard<std::mutex> lk(info_mu_);
    size_t n = std::min(max, log_.size());
    return std::vector<std::string>(log_.end() - long(n), log_.end());
}

std::string Engine::last_summary() {
    std::lock_guard<std::mutex> lk(info_mu_);
    return last_summary_;
}

std::vector<Transfer> Engine::transfers() {
    std::lock_guard<std::mutex> lk(info_mu_);
    std::vector<Transfer> v;
    for (auto& [id, t] : transfers_) v.push_back(t);
    return v;
}

int Engine::transfer_begin(const std::string& what, const std::string& path, uint64_t total, bool queued) {
    std::lock_guard<std::mutex> lk(info_mu_);
    int id = next_transfer_++;
    transfers_[id] = {what, path, 0, total, queued};
    return id;
}

void Engine::transfer_start(int id) {
    std::lock_guard<std::mutex> lk(info_mu_);
    auto it = transfers_.find(id);
    if (it != transfers_.end()) it->second.queued = false;
}

void Engine::transfer_progress(int id, uint64_t done, uint64_t total) {
    std::lock_guard<std::mutex> lk(info_mu_);
    auto it = transfers_.find(id);
    if (it != transfers_.end()) { it->second.done = done; it->second.total = total; }
}

void Engine::transfer_end(int id) {
    std::lock_guard<std::mutex> lk(info_mu_);
    transfers_.erase(id);
}

// ---------------------------------------------------------------------------

int Engine::add_root(const std::string& local_path, const std::string& remote_prefix, const std::string& direction,
                     bool encrypt, std::string& error) {
    std::string abs = real_path(local_path);
    if (abs.empty()) {
        error = "folder does not exist: " + local_path;
        return 0;
    }
    if (!stat_path(abs, true).is_dir) {
        error = "not a folder: " + abs;
        return 0;
    }
    for (auto& r : db_.roots()) {
        if (r.local_path == abs || starts_with(abs, r.local_path + "/") || starts_with(r.local_path, abs + "/")) {
            error = "overlaps an existing tracked folder: " + r.local_path;
            return 0;
        }
    }
    if (direction != "two-way" && direction != "upload-only" && direction != "download-only") {
        error = "direction must be two-way, upload-only or download-only";
        return 0;
    }
    std::string rp = remote_prefix;
    while (!rp.empty() && rp.front() == '/') rp.erase(0, 1);
    while (!rp.empty() && rp.back() == '/') rp.pop_back();
    RootRow r;
    r.local_path = abs;
    r.remote_prefix = rp;
    r.direction = direction;
    r.encrypt = encrypt;
    int id = db_.add_root(r);
    if (!id) error = "could not add root";
    return id;
}

void Engine::scan(const RootRow& root, std::map<std::string, FileRow>& base, std::map<std::string, LocalFile>& out,
                  SyncReport& rep) {
    IgnoreRules ign;
    ign.load_file(root.local_path + "/.s3vaultignore");
    timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);  // ns precision: mtimes are compared against it
    int64_t now_ns = int64_t(ts.tv_sec) * 1000000000LL + ts.tv_nsec;
    std::vector<std::string> stack = {""};
    while (!stack.empty()) {
        std::string rel_dir = stack.back();
        stack.pop_back();
        std::string abs_dir = rel_dir.empty() ? root.local_path : root.local_path + "/" + rel_dir;
        DIR* d = opendir(abs_dir.c_str());
        if (!d) continue;
        while (dirent* e = readdir(d)) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            std::string rel = rel_dir.empty() ? e->d_name : rel_dir + "/" + e->d_name;
            FileStat st = stat_path(abs_dir + "/" + e->d_name);
            if (st.is_link) continue;  // symlinks are not synced
            if (ign.ignored(rel, st.is_dir)) continue;
            if (st.is_dir) {
                stack.push_back(rel);
                continue;
            }
            if (!st.is_file) continue;
            LocalFile lf;
            lf.size = st.size;
            lf.mtime_ns = st.mtime_ns;
            lf.inode = st.inode;
            auto b = base.find(rel);
            if (b != base.end() && b->second.l_size == st.size && b->second.l_mtime == st.mtime_ns &&
                b->second.l_inode == st.inode && !b->second.l_hash.empty()) {
                lf.hash = b->second.l_hash;
            } else {
                // Still being written? Leave it for the next pass.
                if (now_ns - st.mtime_ns < 2000000000LL && now_ns >= st.mtime_ns) {
                    rep.messages.push_back("skipped (still changing): " + rel);
                    rep.retry_soon = true;
                    continue;
                }
                lf.hash = sha256_file(abs_dir + "/" + e->d_name);
                if (lf.hash.empty()) {
                    rep.errors++;
                    rep.messages.push_back("cannot read " + rel);
                    continue;
                }
                // Cache the new stat → hash (base fields untouched).
                FileRow row = b != base.end() ? b->second : FileRow{};
                row.rel = rel;
                row.l_size = st.size;
                row.l_mtime = st.mtime_ns;
                row.l_inode = st.inode;
                row.l_hash = lf.hash;
                if (b != base.end()) {
                    db_.upsert_file(root.id, row);
                    b->second = row;
                }
            }
            out[rel] = lf;
        }
        closedir(d);
    }
}

bool Engine::local_unchanged(const std::string& abs, const LocalFile* planned) {
    FileStat st = stat_path(abs);
    if (!planned) return !st.exists;
    return st.is_file && st.size == planned->size && st.mtime_ns == planned->mtime_ns && st.inode == planned->inode;
}

ConflictRow Engine::make_conflict(const RootRow& root, const PlanInput& in, const std::string& rel,
                                  const std::string& kind) {
    ConflictRow c;
    c.root_id = root.id;
    c.rel = rel;
    c.kind = kind;
    auto l = in.local.find(rel);
    if (l != in.local.end()) {
        c.local_exists = true;
        c.local_size = l->second.size;
        c.local_mtime = l->second.mtime_ns / 1000000000LL;
        c.local_hash = l->second.hash;
    }
    auto r = in.remote.find(rel);
    if (r != in.remote.end()) {
        c.remote_exists = true;
        c.remote_key = r->second.key;
        c.remote_etag = r->second.etag;
        c.remote_size = r->second.size;
        c.remote_mtime = r->second.mtime;
    } else if (auto b = in.base.find(rel); b != in.base.end()) {
        c.remote_key = b->second.remote_key;
    }
    c.detected = int64_t(time(nullptr));
    return c;
}

void Engine::exec_one(const RootRow& root, const PlanInput& in, const Action& a, SyncReport& rep,
                      std::vector<ConflictRow>& conflicts, std::mutex& mu) {
    std::string abs = root.local_path + "/" + a.rel;
    auto li = in.local.find(a.rel);
    const LocalFile* L = li == in.local.end() ? nullptr : &li->second;
    auto bi = in.base.find(a.rel);
    FileRow row = bi != in.base.end() ? bi->second : FileRow{};
    row.rel = a.rel;
    auto note = [&](const std::string& m, bool err) {
        std::lock_guard<std::mutex> lk(mu);
        rep.messages.push_back(m);
        if (err) rep.errors++;
        log(m);
    };
    auto add_conflict = [&](const std::string& kind) {
        std::lock_guard<std::mutex> lk(mu);
        conflicts.push_back(make_conflict(root, in, a.rel, kind));
        rep.conflicts++;
    };
    bool encrypted = ends_with(a.key, ".gpg");
    if (encrypted && !vault_.unlocked() &&
        (a.kind == ActKind::Upload || a.kind == ActKind::Download || a.kind == ActKind::CheckEqual)) {
        std::lock_guard<std::mutex> lk(mu);
        rep.locked_skipped = true;
        return;
    }

    switch (a.kind) {
        case ActKind::Upload: {
            FileStat before = stat_path(abs);
            Conditions c;
            c.if_match = a.if_match;
            c.if_none_match = a.if_none_match;
            int t = transfer_begin("upload", a.rel, before.size);
            OpResult r = vault_.upload_file(abs, a.key, c, [&](uint64_t d, uint64_t tot) { transfer_progress(t, d, tot); });
            transfer_end(t);
            if (!r.ok) {
                // 412: another device got there first; the next pass sees it as a remote change.
                note((r.precondition_failed ? "changed remotely meanwhile, will re-check: " : "upload failed: ") + a.rel +
                         (r.precondition_failed ? "" : " (" + r.error + ")"),
                     !r.precondition_failed);
                if (r.precondition_failed) want_sync_ = true;
                return;
            }
            FileStat after = stat_path(abs);
            bool stable = after.size == before.size && after.mtime_ns == before.mtime_ns && after.inode == before.inode;
            row.remote_key = a.key;
            row.base_etag = r.etag;
            row.base_hash = stable ? r.plain_hash : "";  // unknown → re-upload next pass
            row.l_size = before.size;
            row.l_mtime = before.mtime_ns;
            row.l_inode = before.inode;
            row.l_hash = stable ? r.plain_hash : "";
            db_.upsert_file(root.id, row);
            std::lock_guard<std::mutex> lk(mu);
            rep.uploaded++;
            log("uploaded " + a.rel);
            return;
        }
        case ActKind::Download: {
            auto ri = in.remote.find(a.rel);
            uint64_t total = ri != in.remote.end() ? ri->second.size : 0;
            int t = transfer_begin("download", a.rel, total);
            OpResult r = vault_.download_to(a.key, abs, [&] { return local_unchanged(abs, L); });
            transfer_end(t);
            if (!r.ok) {
                note("download failed: " + a.rel + " (" + r.error + ")", !r.error.empty() && r.error.find("changed during") == std::string::npos);
                return;
            }
            FileStat st = stat_path(abs);
            row.remote_key = a.key;
            row.base_etag = r.etag.empty() && ri != in.remote.end() ? ri->second.etag : r.etag;
            row.base_hash = r.plain_hash;
            row.l_size = st.size;
            row.l_mtime = st.mtime_ns;
            row.l_inode = st.inode;
            row.l_hash = r.plain_hash;
            db_.upsert_file(root.id, row);
            std::lock_guard<std::mutex> lk(mu);
            rep.downloaded++;
            log("downloaded " + a.rel);
            return;
        }
        case ActKind::DeleteLocal: {
            if (!local_unchanged(abs, L)) return;  // changed since the scan; next pass decides
            if (!platform::trash_local(abs)) {
                // No desktop trash: keep a copy inside the root (ignored by sync).
                std::string dst = root.local_path + "/.s3vault-trash/" + format_utc_compact(int64_t(time(nullptr))) + "/" + a.rel;
                mkdirs(path_dirname(dst));
                if (!rename_replace(abs, dst)) {
                    note("cannot remove local " + a.rel, true);
                    return;
                }
            }
            db_.delete_file(root.id, a.rel);
            std::lock_guard<std::mutex> lk(mu);
            rep.deleted_local++;
            log("deleted locally (to trash): " + a.rel);
            return;
        }
        case ActKind::DeleteRemote: {
            OpResult r = vault_.trash_key(a.key, a.if_match);
            if (!r.ok) {
                note(r.precondition_failed ? "changed remotely meanwhile, will re-check: " + a.rel
                                           : "remote delete failed: " + a.rel + " (" + r.error + ")",
                     !r.precondition_failed);
                return;
            }
            db_.delete_file(root.id, a.rel);
            std::lock_guard<std::mutex> lk(mu);
            rep.deleted_remote++;
            log("deleted on server (to vault trash): " + a.rel);
            return;
        }
        case ActKind::CheckEqual: {
            auto ri = in.remote.find(a.rel);
            if (!L || ri == in.remote.end()) return;
            // Plain objects uploaded in one PUT have ETag = MD5; we do not keep MD5, so always compare contents.
            if (ri->second.size > kCompareMax + (1 << 20)) {
                add_conflict(a.conflict_kind);
                return;
            }
            std::string buf;
            int t = transfer_begin("compare", a.rel, ri->second.size);
            OpResult r = vault_.download_to_memory(a.key, buf, kCompareMax);
            transfer_end(t);
            std::string h = r.plain_hash;
            wipe(buf);
            if (!r.ok) {
                if (r.too_large) add_conflict(a.conflict_kind);
                else note("compare failed: " + a.rel + " (" + r.error + ")", true);
                return;
            }
            if (h == L->hash) {
                row.remote_key = a.key;
                row.base_etag = r.etag.empty() ? ri->second.etag : r.etag;
                row.base_hash = h;
                row.l_size = L->size;
                row.l_mtime = L->mtime_ns;
                row.l_inode = L->inode;
                row.l_hash = h;
                db_.upsert_file(root.id, row);
                std::lock_guard<std::mutex> lk(mu);
                rep.unchanged++;
                return;
            }
            add_conflict(a.conflict_kind);
            return;
        }
        case ActKind::ForgetBase:
            db_.delete_file(root.id, a.rel);
            return;
        case ActKind::Conflict:
            add_conflict(a.conflict_kind);
            return;
    }
}

void Engine::run_actions(const RootRow& root, const PlanInput& in, std::vector<Action>& acts, SyncReport& rep,
                         std::vector<ConflictRow>& conflicts) {
    std::mutex mu;
    std::atomic<size_t> next{0};
    int n = std::max(1, std::min(cfg_.sync.concurrency, 32));
    std::vector<std::thread> pool;
    for (int i = 0; i < n; i++) {
        pool.emplace_back([&] {
            for (;;) {
                size_t k = next++;
                if (k >= acts.size() || stop_) return;
                exec_one(root, in, acts[k], rep, conflicts, mu);
            }
        });
    }
    for (auto& t : pool) t.join();
}

SyncReport Engine::sync_root(const RootRow& root, const std::vector<RemoteEntry>& remote) {
    SyncReport rep;
    if (!stat_path(root.local_path, true).is_dir) {
        rep.errors++;
        rep.messages.push_back("tracked folder missing: " + root.local_path + " (not syncing it)");
        return rep;
    }
    PlanInput in;
    in.direction = root.direction;
    in.default_encrypt = root.encrypt;
    in.remote_prefix = root.remote_prefix;
    in.vault_prefix = vault_.prefix();
    in.base = db_.files(root.id);
    scan(root, in.base, in.local, rep);

    IgnoreRules ign;
    ign.load_file(root.local_path + "/.s3vaultignore");
    std::string pfx = root.remote_prefix.empty() ? "" : root.remote_prefix + "/";
    for (auto& e : remote) {
        if (e.dir_marker || !starts_with(e.logical, pfx)) continue;
        std::string rel = e.logical.substr(pfx.size());
        if (rel.empty() || ign.ignored(rel, false)) continue;
        RemoteFile rf{e.key, e.etag, e.size, e.mtime, e.encrypted};
        auto it = in.remote.find(rel);
        if (it != in.remote.end()) {
            // Both "x" and "x.gpg" exist: prefer the one we synced before, else the newer.
            auto b = in.base.find(rel);
            bool keep_old = b != in.base.end() ? b->second.remote_key == it->second.key : it->second.mtime >= rf.mtime;
            rep.messages.push_back("both plain and encrypted copies exist on the server: " + e.logical);
            if (keep_old) continue;
        }
        in.remote[rel] = rf;
    }
    // Base rows for files that were never synced (only cached hashes) are not a base.
    std::vector<Action> acts = plan_sync(in);
    std::vector<ConflictRow> conflicts;
    run_actions(root, in, acts, rep, conflicts);
    db_.set_conflicts(root.id, conflicts);
    return rep;
}

SyncReport Engine::sync_all(bool refresh_remote) {
    std::lock_guard<std::mutex> lk(sync_mu_);
    syncing_ = true;
    SyncReport total;
    std::vector<RemoteEntry> remote;
    if (refresh_remote) {
        OpResult r = vault_.refresh(&remote);
        if (!r.ok) {
            total.errors++;
            total.messages.push_back(r.error);
            log("sync: " + r.error);
            syncing_ = false;
            return total;
        }
    } else {
        remote = vault_.cached_entries();
    }
    for (auto& root : db_.roots()) {
        if (root.paused) continue;
        SyncReport r = sync_root(root, remote);
        total.uploaded += r.uploaded;
        total.downloaded += r.downloaded;
        total.deleted_remote += r.deleted_remote;
        total.deleted_local += r.deleted_local;
        total.conflicts += r.conflicts;
        total.errors += r.errors;
        total.unchanged += r.unchanged;
        total.locked_skipped |= r.locked_skipped;
        total.retry_soon |= r.retry_soon;
        for (auto& m : r.messages) total.messages.push_back(m);
    }
    // Anything uploaded/deleted changes the listing the UI shows.
    if (total.uploaded || total.deleted_remote) vault_.refresh();
    last_sync_ = int64_t(time(nullptr));
    {
        std::lock_guard<std::mutex> ik(info_mu_);
        last_summary_ = total.summary();
    }
    if (total.uploaded || total.downloaded || total.deleted_local || total.deleted_remote || total.errors)
        log("sync: " + total.summary());
    syncing_ = false;
    return total;
}

// ---------------------------------------------------------------------------
// conflict resolution

OpResult Engine::resolve(int64_t id, Resolution how) {
    std::lock_guard<std::mutex> lk(sync_mu_);
    ConflictRow c;
    if (!db_.conflict(id, c)) return OpResult::fail("conflict no longer exists");
    RootRow root;
    bool found = false;
    for (auto& r : db_.roots())
        if (r.id == c.root_id) { root = r; found = true; }
    if (!found) return OpResult::fail("root removed");

    std::string abs = root.local_path + "/" + c.rel;
    std::string logical = root.remote_prefix.empty() ? c.rel : root.remote_prefix + "/" + c.rel;
    auto base_rows = db_.files(root.id);
    FileRow row = base_rows.count(c.rel) ? base_rows[c.rel] : FileRow{};
    row.rel = c.rel;

    // Fresh state of both sides.
    FileStat lst = stat_path(abs);
    bool local = lst.is_file;
    ObjectInfo ro;
    std::string rkey;
    bool remote = false;
    for (const std::string& k : {c.remote_key, vault_.key_for(logical, true), vault_.key_for(logical, false)}) {
        if (k.empty()) continue;
        if (vault_.s3().head(k, &ro).ok()) { rkey = k; remote = true; break; }
    }
    if (!rkey.size()) {
        PlanInput pi;
        pi.default_encrypt = root.encrypt;
        pi.remote_prefix = root.remote_prefix;
        pi.vault_prefix = vault_.prefix();
        rkey = upload_key(pi, c.rel, nullptr, row.remote_key.empty() ? nullptr : &row);
    }
    if (how == Resolution::KeepNewest) {
        if (!local) how = Resolution::KeepRemote;
        else if (!remote) how = Resolution::KeepLocal;
        else how = lst.mtime_ns / 1000000000LL >= ro.mtime ? Resolution::KeepLocal : Resolution::KeepRemote;
    }

    auto upload_local = [&](const std::string& key, const std::string& if_match) -> OpResult {
        Conditions cond;
        if (if_match.empty()) cond.if_none_match = true;
        else cond.if_match = if_match;
        FileStat before = stat_path(abs);
        OpResult r = vault_.upload_file(abs, key, cond);
        if (!r.ok) return r;
        row.remote_key = key;
        row.base_etag = r.etag;
        row.base_hash = r.plain_hash;
        row.l_size = before.size;
        row.l_mtime = before.mtime_ns;
        row.l_inode = before.inode;
        row.l_hash = r.plain_hash;
        db_.upsert_file(root.id, row);
        return r;
    };
    auto download_remote = [&](const std::string& key, const std::string& dest, bool trash_old) -> OpResult {
        OpResult r = vault_.download_to(key, dest, [&] {
            if (trash_old && stat_path(dest).exists) platform::trash_local(dest);
            return true;
        });
        return r;
    };

    OpResult res;
    switch (how) {
        case Resolution::KeepLocal:
            if (local) res = upload_local(rkey, remote ? ro.etag : "");
            else if (remote) {
                res = vault_.trash_key(rkey, ro.etag);
                if (res.ok) db_.delete_file(root.id, c.rel);
            } else res = OpResult::success();
            break;
        case Resolution::KeepRemote:
            if (remote) {
                res = download_remote(rkey, abs, true);
                if (res.ok) {
                    FileStat st = stat_path(abs);
                    row.remote_key = rkey;
                    row.base_etag = res.etag.empty() ? ro.etag : res.etag;
                    row.base_hash = res.plain_hash;
                    row.l_size = st.size;
                    row.l_mtime = st.mtime_ns;
                    row.l_inode = st.inode;
                    row.l_hash = res.plain_hash;
                    db_.upsert_file(root.id, row);
                }
            } else if (local) {
                res = platform::trash_local(abs) ? OpResult::success() : OpResult::fail("cannot move local file to trash");
                if (res.ok) db_.delete_file(root.id, c.rel);
            } else res = OpResult::success();
            break;
        case Resolution::KeepBoth:
        case Resolution::KeepNewest:
            if (local && remote) {
                // Server copy → "name (conflict remote …).ext" (server-side copy + download), then local → original.
                bool enc = ends_with(rkey, ".gpg");
                std::string alt_logical = Vault::conflict_name(logical, "remote");
                std::string alt_key = vault_.key_for(alt_logical, enc);
                S3Result cp = vault_.s3().copy(rkey, alt_key);
                if (!cp.ok()) { res = OpResult::fail("copy: " + cp.describe()); break; }
                std::string alt_rel = root.remote_prefix.empty() ? alt_logical : alt_logical.substr(root.remote_prefix.size() + 1);
                std::string alt_abs = root.local_path + "/" + alt_rel;
                OpResult d = vault_.download_to(alt_key, alt_abs);
                if (d.ok) {
                    FileStat st = stat_path(alt_abs);
                    FileRow ar;
                    ar.rel = alt_rel;
                    ar.remote_key = alt_key;
                    ar.base_etag = cp.etag.empty() ? d.etag : cp.etag;
                    ar.base_hash = d.plain_hash;
                    ar.l_size = st.size;
                    ar.l_mtime = st.mtime_ns;
                    ar.l_inode = st.inode;
                    ar.l_hash = d.plain_hash;
                    db_.upsert_file(root.id, ar);
                }
                res = upload_local(rkey, ro.etag);
            } else if (remote) {
                res = download_remote(rkey, abs, false);
                if (res.ok) {
                    FileStat st = stat_path(abs);
                    row.remote_key = rkey;
                    row.base_etag = res.etag.empty() ? ro.etag : res.etag;
                    row.base_hash = res.plain_hash;
                    row.l_size = st.size;
                    row.l_mtime = st.mtime_ns;
                    row.l_inode = st.inode;
                    row.l_hash = res.plain_hash;
                    db_.upsert_file(root.id, row);
                }
            } else if (local) {
                res = upload_local(rkey, "");
            } else res = OpResult::success();
            break;
    }
    if (res.ok) {
        db_.delete_conflict(id);
        log(std::string("resolved (") + resolution_name(how) + "): " + c.rel);
    } else if (res.precondition_failed) {
        res.error = "the server copy changed again; sync and review this conflict";
    }
    return res;
}

// ---------------------------------------------------------------------------
// background loop

void Engine::request_sync() {
    want_sync_ = true;
    wake_.notify_all();
}

void Engine::start() {
    if (running_) return;
    stop_ = false;
    running_ = true;
    watcher_ = new platform::FsWatcher();
    watch_thread_ = std::thread([this] {
        // Adding recursive inotify watches can take a while on big trees: do it here, not on the caller's thread.
        for (auto& r : db_.roots())
            if (!r.paused && !stop_) watcher_->add_root(r.id, r.local_path);
        watches_ready_ = true;
        auto last_event = std::chrono::steady_clock::time_point{};
        bool pending = false;
        while (!stop_) {
            bool overflow = false;
            auto ev = watcher_->poll(500, overflow);
            bool relevant = overflow;
            for (auto& e : ev)
                if (e.rel_path.find(".s3v-tmp") == std::string::npos) relevant = true;
            if (relevant) {
                pending = true;
                last_event = std::chrono::steady_clock::now();
            }
            // Debounce: sync once changes have been quiet for 2.5 s (files younger than 2 s are skipped).
            if (pending && std::chrono::steady_clock::now() - last_event > std::chrono::milliseconds(2500)) {
                pending = false;
                request_sync();
            }
        }
    });
    thread_ = std::thread([this] { loop(); });
}

void Engine::stop() {
    if (!running_) return;
    stop_ = true;
    if (vault_.connected()) vault_.s3().cancel = true;  // abort uploads/downloads in flight
    wake_.notify_all();
    if (thread_.joinable()) thread_.join();
    if (watch_thread_.joinable()) watch_thread_.join();
    if (vault_.connected()) vault_.s3().cancel = false;
    delete watcher_;
    watcher_ = nullptr;
    running_ = false;
}

void Engine::loop() {
    want_sync_ = true;  // initial pass
    auto next_poll = std::chrono::steady_clock::now();
    size_t known_roots = db_.roots().size();
    while (!stop_) {
        {
            std::unique_lock<std::mutex> lk(wake_mu_);
            wake_.wait_until(lk, next_poll, [this] { return stop_ || want_sync_; });
        }
        if (stop_) break;
        // New roots added from the UI need watches (once the initial ones are in place).
        auto roots = db_.roots();
        if (watches_ready_ && roots.size() != known_roots) {
            for (auto& r : roots) {
                watcher_->remove_root(r.id);
                if (!r.paused) watcher_->add_root(r.id, r.local_path);
            }
            known_roots = roots.size();
        }
        want_sync_ = false;
        SyncReport rep = sync_all(true);
        if (on_synced) on_synced();
        next_poll = std::chrono::steady_clock::now() +
                    (rep.retry_soon ? std::chrono::seconds(3) : std::chrono::seconds(std::max(10, cfg_.sync.poll_seconds)));
    }
}

}  // namespace s3v
