#include "edit/edit.h"

#include <ctime>

#include "platform.h"
#include "util/sha256.h"
#include "util/strings.h"

namespace s3v {

int EditManager::open(const RemoteEntry& e, std::string& error, bool launch) {
    int id;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& [k, s] : s_)
            if (s.key == e.key) {
                // Already open: just bring the editor up again.
                id = k;
                if (launch) platform::launch_editor(cfg_.deps.editor, cfg_.deps.terminal, s.path, &error);
                return id;
            }
        id = next_++;
    }
    std::string dir = platform::session_tmp_dir() + "/edit/" + std::to_string(id);
    mkdirs(dir, 0700);
    std::string path = dir + "/" + path_basename(e.logical);
    OpResult r = vault_.download_to(e.key, path);
    if (!r.ok) {
        error = r.error;
        remove_tree(dir, !platform::session_tmp_in_ram());
        return 0;
    }
    EditSession s;
    s.id = id;
    s.logical = e.logical;
    s.key = e.key;
    s.etag_at_open = r.etag.empty() ? e.etag : r.etag;
    s.hash_at_open = r.plain_hash;
    s.current_hash = r.plain_hash;
    s.path = path;
    s.opened_at = int64_t(time(nullptr));
    s.last_stat = stat_path(path);
    {
        std::lock_guard<std::mutex> lk(mu_);
        s_[id] = s;
    }
    if (launch && !platform::launch_editor(cfg_.deps.editor, cfg_.deps.terminal, path, &error)) {
        // Keep the session: the user can retry or open it another way.
        std::lock_guard<std::mutex> lk(mu_);
        s_[id].error = error;
    }
    return id;
}

bool EditManager::relaunch(int id, std::string& error) {
    std::string p;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = s_.find(id);
        if (it == s_.end()) return false;
        p = it->second.path;
    }
    return platform::launch_editor(cfg_.deps.editor, cfg_.deps.terminal, p, &error);
}

void EditManager::poll() {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto& [id, s] : s_) {
        FileStat st = stat_path(s.path, true);
        if (!st.exists) continue;  // editor mid-save (write temp + rename): look again next time
        if (st.size == s.last_stat.size && st.mtime_ns == s.last_stat.mtime_ns && st.inode == s.last_stat.inode) continue;
        s.last_stat = st;
        std::string h = sha256_file(s.path);
        if (h.empty() || h == s.current_hash) continue;
        s.current_hash = h;
        bool was = s.changed;
        s.changed = h != s.hash_at_open;
        if (s.changed) s.prompt = true;
        (void)was;
    }
}

std::vector<EditSession> EditManager::sessions() {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<EditSession> v;
    for (auto& [id, s] : s_) v.push_back(s);
    return v;
}

bool EditManager::get(int id, EditSession& out) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = s_.find(id);
    if (it == s_.end()) return false;
    out = it->second;
    return true;
}

void EditManager::clear_prompt(int id) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = s_.find(id);
    if (it != s_.end()) it->second.prompt = false;
}

OpResult EditManager::save_back(int id, bool force) {
    EditSession s;
    if (!get(id, s)) return OpResult::fail("edit session closed");
    Conditions c;
    if (!force) c.if_match = s.etag_at_open;
    OpResult r = vault_.upload_file(s.path, s.key, c);
    std::lock_guard<std::mutex> lk(mu_);
    auto it = s_.find(id);
    if (it == s_.end()) return r;
    if (!r.ok) {
        it->second.conflict = r.precondition_failed;
        it->second.error = r.precondition_failed ? "the file was changed on the server since you opened it" : r.error;
        return r;
    }
    it->second.etag_at_open = r.etag;
    it->second.hash_at_open = r.plain_hash;
    it->second.current_hash = r.plain_hash;
    it->second.changed = false;
    it->second.prompt = false;
    it->second.conflict = false;
    it->second.error.clear();
    return r;
}

OpResult EditManager::save_as_copy(int id) {
    EditSession s;
    if (!get(id, s)) return OpResult::fail("edit session closed");
    std::string alt = Vault::conflict_name(s.logical, "edited");
    Conditions c;
    c.if_none_match = true;
    OpResult r = vault_.upload_file(s.path, vault_.key_for(alt, ends_with(s.key, ".gpg")), c);
    if (r.ok) discard(id);
    return r;
}

OpResult EditManager::reload(int id) {
    EditSession s;
    if (!get(id, s)) return OpResult::fail("edit session closed");
    OpResult r = vault_.download_to(s.key, s.path);
    if (!r.ok) return r;
    std::lock_guard<std::mutex> lk(mu_);
    auto it = s_.find(id);
    if (it == s_.end()) return r;
    it->second.etag_at_open = r.etag;
    it->second.hash_at_open = r.plain_hash;
    it->second.current_hash = r.plain_hash;
    it->second.changed = it->second.prompt = it->second.conflict = false;
    it->second.error.clear();
    it->second.last_stat = stat_path(s.path);
    return r;
}

void EditManager::discard(int id) {
    std::string dir;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = s_.find(id);
        if (it == s_.end()) return;
        dir = path_dirname(it->second.path);
        s_.erase(it);
    }
    remove_tree(dir, !platform::session_tmp_in_ram());
}

void EditManager::close_all() {
    std::vector<int> ids;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& [id, s] : s_) ids.push_back(id);
    }
    for (int id : ids) discard(id);
}

bool EditManager::any_unsaved() {
    poll();
    std::lock_guard<std::mutex> lk(mu_);
    for (auto& [id, s] : s_)
        if (s.changed) return true;
    return false;
}

}  // namespace s3v
