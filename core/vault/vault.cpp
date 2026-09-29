#include "vault/vault.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <set>

#include "platform.h"
#include "util/fs.h"
#include "util/sha256.h"
#include "util/strings.h"

namespace s3v {

static const char* kKeyMagic = "s3vault-key-v1\n";

Vault::Vault(Config& cfg, Db& db) : cfg_(cfg), db_(db), gpg_(cfg.deps.gpg) {
    std::string p = cfg.storage.prefix;
    while (!p.empty() && p.front() == '/') p.erase(0, 1);
    while (!p.empty() && p.back() == '/') p.pop_back();
    prefix_ = p.empty() ? "" : p + "/";
    keys_.configure(PassCache::parse_mode(cfg.security.remember), cfg.security.idle_minutes);
}

Vault::~Vault() = default;

std::string Vault::secret_account(const StorageConfig& s) { return "s3:" + s.provider + ":" + s.access_key_id; }
std::string Vault::vault_account() const { return "vault:" + cfg_.storage.bucket + "/" + prefix_; }

bool Vault::connect(std::string& error) {
    std::string secret;
    if (const char* e = getenv("S3VAULT_SECRET_KEY"); e && *e) {
        secret = e;
    } else {
        SecureString s;
        if (platform::keychain_load(secret_account(cfg_.storage), s)) secret = std::string(s.view());
    }
    S3Endpoint ep;
    if (!resolve_endpoint(cfg_.storage, secret, ep, error)) {
        wipe(secret);
        return false;
    }
    wipe(secret);
    s3_ = std::make_unique<S3Client>(std::move(ep));
    if (cfg_.sync.bandwidth_kbps > 0)
        s3_->max_bytes_per_sec = int64_t(cfg_.sync.bandwidth_kbps) * 1024 / std::max(1, cfg_.sync.concurrency);
    return true;
}

std::string Vault::key_for(const std::string& logical, bool encrypted) const {
    return prefix_ + logical + (encrypted ? ".gpg" : "");
}

bool Vault::parse_key(const std::string& key, RemoteEntry& e) const {
    if (!starts_with(key, prefix_)) return false;
    std::string rel = key.substr(prefix_.size());
    if (rel.empty() || starts_with(rel, ".s3vault/") || rel == ".s3vault") return false;
    e.key = key;
    e.dir_marker = rel.back() == '/';
    if (e.dir_marker) {
        rel.pop_back();
        e.logical = rel;
        e.encrypted = false;
        return !rel.empty();
    }
    e.encrypted = ends_with(rel, ".gpg");
    e.logical = e.encrypted ? rel.substr(0, rel.size() - 4) : rel;
    return !e.logical.empty();
}

std::string Vault::conflict_name(const std::string& logical, const std::string& tag) {
    std::string dir = path_dirname(logical), base = path_basename(logical);
    size_t dot = base.rfind('.');
    std::string stem = dot == std::string::npos || dot == 0 ? base : base.substr(0, dot);
    std::string ext = dot == std::string::npos || dot == 0 ? "" : base.substr(dot);
    time_t t = time(nullptr);
    struct tm tmv {};
    localtime_r(&t, &tmv);
    char ts[32];
    strftime(ts, sizeof ts, "%Y-%m-%d %H%M%S", &tmv);
    std::string name = stem + " (conflict " + tag + " " + ts + ")" + ext;
    return dir.empty() ? name : dir + "/" + name;
}

std::string Vault::staging_dir() const {
    std::string d = data_dir() + "/staging";
    mkdirs(d, 0700);
    return d;
}

// ---------------------------------------------------------------------------
// vault.json / key.gpg

OpResult Vault::load_info(bool& exists) {
    exists = false;
    if (!s3_) return OpResult::fail("not connected");
    std::string body;
    S3Result r = s3_->get_string(prefix_ + ".s3vault/vault.json", body, 1 << 20);
    if (r.not_found()) return OpResult::success();
    if (!r.ok()) return OpResult::fail("read vault.json: " + r.describe());
    exists = true;
    ObjectInfo oi;
    S3Result h = s3_->head(prefix_ + ".s3vault/key.gpg", &oi);
    has_key_ = h.ok();
    return OpResult::success();
}

OpResult Vault::init(const std::string& password) {
    if (!s3_) return OpResult::fail("not connected");
    std::string id = to_hex(random_bytes(16));
    char json[512];
    snprintf(json, sizeof json,
             "{\n  \"format\": 1,\n  \"vault_id\": \"%s\",\n  \"created\": %lld,\n  \"created_by\": \"%s\",\n"
             "  \"encryption\": \"openpgp-symmetric\",\n  \"key\": \".s3vault/key.gpg\"\n}\n",
             id.c_str(), static_cast<long long>(time(nullptr)), cfg_.device().c_str());
    Conditions c;
    c.if_none_match = true;
    S3Result r = s3_->put_string(prefix_ + ".s3vault/vault.json", json, c);
    if (r.precondition_failed()) return OpResult::fail("a vault already exists at " + prefix_);
    if (!r.ok()) return OpResult::fail("write vault.json: " + r.describe());
    if (!password.empty()) return set_password("", password);
    return OpResult::success();
}

OpResult Vault::set_password(const std::string& old_password, const std::string& new_password) {
    if (!s3_) return OpResult::fail("not connected");
    if (!gpg_.available()) return OpResult::fail("gpg not found (deps.gpg)");
    std::string key_obj = prefix_ + ".s3vault/key.gpg";
    std::string vault_key, etag;
    Conditions c;
    std::string cur;
    S3Result r = s3_->get(key_obj, [&](const char* p, size_t n) { cur.append(p, n); return cur.size() < (1 << 20); }, &etag);
    if (r.ok()) {
        // Change password: decrypt with the old one.
        CryptoResult d = gpg_.decrypt_string(cur, vault_key, old_password, 4096);
        if (d.status == CryptoStatus::BadPassphrase) { OpResult f = OpResult::fail("wrong current password"); f.bad_key = true; return f; }
        if (!d.ok() || !starts_with(vault_key, kKeyMagic)) return OpResult::fail("cannot read key.gpg: " + d.detail);
        c.if_match = etag;
    } else if (r.not_found()) {
        vault_key = std::string(kKeyMagic) + to_hex(random_bytes(32)) + "\n";
        c.if_none_match = true;
    } else {
        return OpResult::fail("read key.gpg: " + r.describe());
    }
    std::string enc;
    CryptoResult e = gpg_.encrypt_string(vault_key, enc, new_password, /*strong_s2k=*/true);
    if (!e.ok()) {
        wipe(vault_key);
        return OpResult::fail("gpg: " + e.detail);
    }
    S3Result w = s3_->put_string(key_obj, enc, c);
    if (!w.ok()) {
        wipe(vault_key);
        OpResult f = OpResult::fail(w.precondition_failed() ? "key.gpg changed on another device; try again"
                                                            : "write key.gpg: " + w.describe());
        f.precondition_failed = w.precondition_failed();
        return f;
    }
    has_key_ = true;
    std::string k = trim(vault_key.substr(strlen(kKeyMagic)));
    keys_.set(k);
    wipe(k);
    wipe(vault_key);
    // A cached keychain copy stays valid (same vault key); nothing else to re-encrypt.
    return OpResult::success();
}

OpResult Vault::unlock(const std::string& password) {
    if (!s3_) return OpResult::fail("not connected");
    std::string cur;
    S3Result r = s3_->get_string(prefix_ + ".s3vault/key.gpg", cur, 1 << 20);
    if (r.not_found()) return OpResult::fail("this vault has no password yet (set one first)");
    if (!r.ok()) return OpResult::fail("read key.gpg: " + r.describe());
    std::string vault_key;
    CryptoResult d = gpg_.decrypt_string(cur, vault_key, password, 4096);
    if (d.status == CryptoStatus::BadPassphrase) {
        OpResult f = OpResult::fail("wrong password");
        f.bad_key = true;
        return f;
    }
    if (!d.ok() || !starts_with(vault_key, kKeyMagic)) return OpResult::fail("cannot read key.gpg: " + d.detail);
    std::string k = trim(vault_key.substr(strlen(kKeyMagic)));
    keys_.set(k);
    if (keys_.mode() == PassCache::Mode::Keychain && cfg_.security.keychain_days > 0)
        platform::keychain_store(vault_account(), k, int64_t(time(nullptr)) + int64_t(cfg_.security.keychain_days) * 86400);
    wipe(k);
    wipe(vault_key);
    has_key_ = true;
    return OpResult::success();
}

bool Vault::try_unlock_from_keychain() {
    if (keys_.mode() != PassCache::Mode::Keychain) return false;
    SecureString s;
    if (!platform::keychain_load(vault_account(), s)) return false;
    keys_.set(s.view());
    return true;
}

void Vault::lock() {
    keys_.lock();
    platform::keychain_erase(vault_account());
}

OpResult Vault::need_key(SecureString& k) {
    k = keys_.get();
    if (!k.empty()) return OpResult::success();
    OpResult f = OpResult::fail("vault is locked; unlock with your password");
    f.locked = true;
    return f;
}

// ---------------------------------------------------------------------------
// listing

OpResult Vault::refresh(std::vector<RemoteEntry>* out) {
    if (!s3_) return OpResult::fail("not connected");
    std::vector<ObjectInfo> objs;
    S3Result r = s3_->list_all(prefix_, objs);
    if (!r.ok()) return OpResult::fail("list: " + r.describe());
    db_.set_remote_cache(objs, int64_t(time(nullptr)));
    if (out) {
        out->clear();
        for (auto& o : objs) {
            RemoteEntry e;
            if (!parse_key(o.key, e)) continue;
            e.size = o.size;
            e.etag = o.etag;
            e.mtime = o.mtime;
            out->push_back(std::move(e));
        }
    }
    return OpResult::success();
}

std::vector<RemoteEntry> Vault::cached_entries() {
    std::vector<RemoteEntry> out;
    for (auto& o : db_.remote_cache()) {
        RemoteEntry e;
        if (!parse_key(o.key, e)) continue;
        e.size = o.size;
        e.etag = o.etag;
        e.mtime = o.mtime;
        out.push_back(std::move(e));
    }
    return out;
}

// ---------------------------------------------------------------------------
// transfers

OpResult Vault::upload_file(const std::string& local, const std::string& key, const Conditions& c,
                            const Progress& progress) {
    if (!s3_) return OpResult::fail("not connected");
    FileStat st = stat_path(local, true);
    if (!st.is_file) return OpResult::fail("not a regular file: " + local);
    OpResult res;
    res.plain_hash = sha256_file(local);
    res.plain_size = st.size;
    if (res.plain_hash.empty()) return OpResult::fail("cannot read " + local);
    std::string src = local;
    std::string staged;
    if (ends_with(key, ".gpg")) {
        SecureString k;
        OpResult kr = need_key(k);
        if (!kr.ok) return kr;
        staged = staging_dir() + "/" + to_hex(random_bytes(8)) + ".gpg";
        bool compress = !Gpg::is_compressed_ext(path_ext_lower(local));
        CryptoResult e = gpg_.encrypt_file(local, staged, k.view(), compress);
        keys_.release_if_ask();
        if (!e.ok()) {
            unlink(staged.c_str());
            return OpResult::fail("encrypt: " + e.detail);
        }
        src = staged;
    }
    S3Result r = s3_->put_file(key, src, c, progress);
    if (!staged.empty()) unlink(staged.c_str());
    if (!r.ok()) {
        OpResult f = OpResult::fail("upload " + key + ": " + r.describe());
        f.precondition_failed = r.precondition_failed();
        return f;
    }
    res.ok = true;
    res.etag = r.etag;
    return res;
}

OpResult Vault::download_to(const std::string& key, const std::string& dest, const std::function<bool()>& before_commit) {
    if (!s3_) return OpResult::fail("not connected");
    std::string dir = path_dirname(dest);
    if (!dir.empty()) mkdirs(dir);
    std::string tmp = (dir.empty() ? "" : dir + "/") + "." + path_basename(dest) + ".s3v-tmp";
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return OpResult::fail("cannot write " + tmp);
    bool encrypted = ends_with(key, ".gpg");
    OpResult res;
    S3Result r;
    std::string etag;
    if (encrypted) {
        SecureString k;
        OpResult kr = need_key(k);
        if (!kr.ok) { close(fd); unlink(tmp.c_str()); return kr; }
        Gpg::Decryptor d;
        std::string err;
        if (!gpg_.start_decrypt(d, k.view(), fd, size_t(-1), &err)) {
            close(fd); unlink(tmp.c_str());
            return OpResult::fail("gpg: " + err);
        }
        r = s3_->get(key, [&](const char* p, size_t n) { return d.write(p, n); }, &etag);
        CryptoResult cr = r.ok() ? d.finish() : (d.abort(), CryptoResult{});
        keys_.release_if_ask();
        close(fd);
        if (r.ok() && !cr.ok()) {
            secure_unlink(tmp);
            OpResult f = OpResult::fail("decrypt " + key + ": " + cr.detail);
            f.bad_key = cr.status == CryptoStatus::BadPassphrase;
            return f;
        }
    } else {
        r = s3_->get(key, [&](const char* p, size_t n) { return write_all_fd(fd, p, n); }, &etag);
        fsync(fd);
        close(fd);
    }
    if (!r.ok()) {
        unlink(tmp.c_str());
        return OpResult::fail("download " + key + ": " + r.describe());
    }
    res.plain_hash = sha256_file(tmp);
    res.plain_size = stat_path(tmp).size;
    res.etag = etag;
    if (before_commit && !before_commit()) {
        unlink(tmp.c_str());
        return OpResult::fail("local file changed during download");
    }
    chmod(tmp.c_str(), 0644);
    if (::rename(tmp.c_str(), dest.c_str()) != 0) {
        unlink(tmp.c_str());
        return OpResult::fail("cannot replace " + dest);
    }
    res.ok = true;
    return res;
}

OpResult Vault::download_to_memory(const std::string& key, std::string& out, size_t max) {
    if (!s3_) return OpResult::fail("not connected");
    out.clear();
    std::string etag;
    OpResult res;
    if (ends_with(key, ".gpg")) {
        SecureString k;
        OpResult kr = need_key(k);
        if (!kr.ok) return kr;
        Gpg::Decryptor d;
        std::string err;
        if (!gpg_.start_decrypt(d, k.view(), -1, max, &err)) return OpResult::fail("gpg: " + err);
        // Ciphertext is at most slightly larger than plaintext (compression can shrink it a lot, hence
        // the cap is enforced on gpg's output as well).
        size_t got = 0;
        S3Result r = s3_->get(key, [&](const char* p, size_t n) {
            got += n;
            if (got > max + (1 << 20) && max < (size_t(1) << 40)) return false;
            return d.write(p, n);
        }, &etag);
        if (!r.ok()) {
            d.abort();
            keys_.release_if_ask();
            OpResult f = OpResult::fail(r.code == "Aborted" ? "too large to preview" : "download: " + r.describe());
            f.too_large = r.code == "Aborted";
            return f;
        }
        CryptoResult cr = d.finish();
        keys_.release_if_ask();
        if (!cr.ok()) {
            OpResult f = OpResult::fail("decrypt: " + cr.detail);
            f.bad_key = cr.status == CryptoStatus::BadPassphrase;
            f.too_large = cr.status == CryptoStatus::TooLarge;
            return f;
        }
        out = d.take_output();
    } else {
        S3Result r = s3_->get(key, [&](const char* p, size_t n) {
            if (out.size() + n > max) return false;
            out.append(p, n);
            return true;
        }, &etag);
        if (!r.ok()) {
            wipe(out);
            OpResult f = OpResult::fail(r.code == "Aborted" ? "too large to preview" : "download: " + r.describe());
            f.too_large = r.code == "Aborted";
            return f;
        }
    }
    res.ok = true;
    res.etag = etag;
    res.plain_hash = sha256_hex(out);
    res.plain_size = out.size();
    return res;
}

// ---------------------------------------------------------------------------
// logical operations

OpResult Vault::mkdir(const std::string& logical_dir) {
    if (!s3_) return OpResult::fail("not connected");
    std::string d = logical_dir;
    while (!d.empty() && d.back() == '/') d.pop_back();
    if (d.empty()) return OpResult::fail("empty folder name");
    S3Result r = s3_->put_string(prefix_ + d + "/", "");
    if (!r.ok()) return OpResult::fail("create folder: " + r.describe());
    return OpResult::success();
}

OpResult Vault::trash_key(const std::string& key, const std::string& expected_etag) {
    if (!expected_etag.empty()) {
        ObjectInfo oi;
        S3Result h = s3_->head(key, &oi);
        if (h.not_found()) return OpResult::success();
        if (!h.ok()) return OpResult::fail("head " + key + ": " + h.describe());
        if (oi.etag != expected_etag) {
            OpResult f = OpResult::fail(key + " changed on the server");
            f.precondition_failed = true;
            return f;
        }
    }
    std::string rel = key.substr(prefix_.size());
    std::string tkey = prefix_ + ".s3vault/trash/" + format_utc_compact(int64_t(time(nullptr))) + "/" + rel;
    if (!ends_with(key, "/")) {
        S3Result c = s3_->copy(key, tkey);
        if (c.not_found()) return OpResult::success();
        if (!c.ok()) return OpResult::fail("copy to trash: " + c.describe());
        if (!expected_etag.empty() && !c.etag.empty() && c.etag != expected_etag) {
            // Someone replaced the object between HEAD and COPY: keep both, do not delete.
            OpResult f = OpResult::fail(key + " changed on the server");
            f.precondition_failed = true;
            return f;
        }
    }
    S3Result d = s3_->del(key);
    if (!d.ok() && !d.not_found()) return OpResult::fail("delete: " + d.describe());
    return OpResult::success();
}

OpResult Vault::remove(const std::string& logical) {
    if (!s3_) return OpResult::fail("not connected");
    std::vector<RemoteEntry> all;
    OpResult lr = refresh(&all);
    if (!lr.ok) return lr;
    int n = 0;
    for (auto& e : all) {
        bool hit = e.logical == logical || starts_with(e.logical, logical + "/");
        if (!hit) continue;
        OpResult r = trash_key(e.key);
        if (!r.ok) return r;
        n++;
    }
    if (!n) return OpResult::fail("not found: " + logical);
    refresh();
    return OpResult::success();
}

OpResult Vault::rename(const std::string& from, const std::string& to) {
    if (!s3_) return OpResult::fail("not connected");
    if (from == to || to.empty()) return OpResult::fail("invalid destination");
    if (starts_with(to, from + "/")) return OpResult::fail("cannot move a folder into itself");
    std::vector<RemoteEntry> all;
    OpResult lr = refresh(&all);
    if (!lr.ok) return lr;
    std::set<std::string> existing;
    for (auto& e : all) existing.insert(e.logical);
    std::vector<std::pair<RemoteEntry, std::string>> moves;
    for (auto& e : all) {
        std::string dst;
        if (e.logical == from) dst = to;
        else if (starts_with(e.logical, from + "/")) dst = to + e.logical.substr(from.size());
        else continue;
        if (existing.count(dst)) return OpResult::fail("already exists: " + dst);
        moves.push_back({e, dst});
    }
    if (moves.empty()) return OpResult::fail("not found: " + from);
    for (auto& [e, dst] : moves) {
        std::string dkey = e.dir_marker ? prefix_ + dst + "/" : key_for(dst, e.encrypted);
        if (!e.dir_marker) {
            S3Result c = s3_->copy(e.key, dkey);
            if (!c.ok()) return OpResult::fail("copy " + e.logical + ": " + c.describe());
        } else {
            s3_->put_string(dkey, "");
        }
        S3Result d = s3_->del(e.key);
        if (!d.ok() && !d.not_found()) return OpResult::fail("delete " + e.logical + ": " + d.describe());
    }
    refresh();
    return OpResult::success();
}

std::vector<TrashEntry> Vault::trash_list(OpResult* err) {
    std::vector<TrashEntry> out;
    std::vector<ObjectInfo> objs;
    std::string tp = prefix_ + ".s3vault/trash/";
    S3Result r = s3_ ? s3_->list_all(tp, objs) : S3Result{};
    if (!r.ok()) {
        if (err) *err = OpResult::fail("list trash: " + r.describe());
        return out;
    }
    for (auto& o : objs) {
        std::string rest = o.key.substr(tp.size());
        size_t sl = rest.find('/');
        if (sl == std::string::npos) continue;
        TrashEntry t;
        t.key = o.key;
        std::string ts = rest.substr(0, sl);  // 20260929T054255Z
        struct tm tmv {};
        if (strptime(ts.c_str(), "%Y%m%dT%H%M%SZ", &tmv)) t.deleted_at = timegm(&tmv);
        t.original = prefix_ + rest.substr(sl + 1);
        RemoteEntry e;
        if (!parse_key(t.original, e)) continue;
        t.logical = e.logical;
        t.encrypted = e.encrypted;
        t.size = o.size;
        out.push_back(t);
    }
    std::sort(out.begin(), out.end(), [](const TrashEntry& a, const TrashEntry& b) { return a.deleted_at > b.deleted_at; });
    if (err) err->ok = true;
    return out;
}

OpResult Vault::restore(const TrashEntry& t) {
    if (!s3_) return OpResult::fail("not connected");
    std::string dst = t.original;
    ObjectInfo oi;
    if (s3_->head(dst, &oi).ok()) dst = key_for(conflict_name(t.logical, "restored"), t.encrypted);
    S3Result c = s3_->copy(t.key, dst);
    if (!c.ok()) return OpResult::fail("restore: " + c.describe());
    s3_->del(t.key);
    refresh();
    return OpResult::success();
}

OpResult Vault::purge_trash(int older_than_days, int* purged) {
    OpResult err;
    auto list = trash_list(&err);
    if (!err.ok) return err;
    int64_t cutoff = int64_t(time(nullptr)) - int64_t(older_than_days) * 86400;
    int n = 0;
    for (auto& t : list) {
        if (t.deleted_at > cutoff) continue;
        if (s3_->del(t.key).ok()) n++;
    }
    if (purged) *purged = n;
    return OpResult::success();
}

}  // namespace s3v
