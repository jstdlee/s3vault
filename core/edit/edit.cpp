#include "edit/edit.h"

#include <algorithm>

#include "preview/preview.h"
#include "util/secure.h"
#include "util/strings.h"

namespace s3v {

int EditManager::open(const RemoteEntry& e, std::string& error) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& [id, d] : docs_)
            if (d.key == e.key) return id;  // already open
    }
    size_t cap = size_t(std::max(1, cfg_.preview.text_max_mb)) << 20;
    std::string text;
    OpResult r = load_preview_bytes(vault_, e, cap, text);
    if (!r.ok) {
        error = r.error;
        return 0;
    }
    if (!utf8_valid(text)) {
        wipe(text);
        error = "not a UTF-8 text file; the built-in editor only edits text";
        return 0;
    }
    std::lock_guard<std::mutex> lk(mu_);
    int id = next_++;
    EditDoc& d = docs_[id];
    d.id = id;
    d.logical = e.logical;
    d.key = e.key;
    d.etag_at_open = r.etag.empty() ? e.etag : r.etag;
    d.saved = text;
    d.text = std::move(text);
    return id;
}

EditDoc* EditManager::doc(int id) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = docs_.find(id);
    return it == docs_.end() ? nullptr : &it->second;
}

std::vector<int> EditManager::ids() {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<int> v;
    for (auto& [id, d] : docs_) v.push_back(id);
    return v;
}

bool EditManager::any_dirty() {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto& [id, d] : docs_)
        if (d.dirty()) return true;
    return false;
}

OpResult EditManager::save(int id, const std::string& text, bool force) {
    std::string key, etag;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = docs_.find(id);
        if (it == docs_.end()) return OpResult::fail("document closed");
        key = it->second.key;
        etag = it->second.etag_at_open;
    }
    Conditions c;
    if (!force) c.if_match = etag;
    return vault_.upload_bytes(text, key, c);
}

OpResult EditManager::save_as_copy(int id, const std::string& text) {
    std::string key, logical;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = docs_.find(id);
        if (it == docs_.end()) return OpResult::fail("document closed");
        key = it->second.key;
        logical = it->second.logical;
    }
    Conditions c;
    c.if_none_match = true;
    return vault_.upload_bytes(text, vault_.key_for(Vault::conflict_name(logical, "edited"), ends_with(key, ".gpg")), c);
}

OpResult EditManager::reload(int id, std::string& text_out, std::string& etag_out) {
    std::string key;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = docs_.find(id);
        if (it == docs_.end()) return OpResult::fail("document closed");
        key = it->second.key;
    }
    size_t cap = size_t(std::max(1, cfg_.preview.text_max_mb)) << 20;
    OpResult r = vault_.download_to_memory(key, text_out, cap);
    etag_out = r.etag;
    return r;
}

void EditManager::apply_saved(int id, const std::string& text, const std::string& etag) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = docs_.find(id);
    if (it == docs_.end()) return;
    wipe(it->second.saved);
    it->second.saved = text;
    it->second.etag_at_open = etag;
    it->second.conflict = false;
    it->second.error.clear();
}

void EditManager::close(int id) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = docs_.find(id);
    if (it == docs_.end()) return;
    wipe(it->second.text);
    wipe(it->second.saved);
    docs_.erase(it);
}

void EditManager::close_all() {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto& [id, d] : docs_) {
        wipe(d.text);
        wipe(d.saved);
    }
    docs_.clear();
}

}  // namespace s3v
