// Vault key replacement ("rotation"). See the comment above RotationStatus in vault.h.
//
// Objects under <prefix>/.s3vault/ while a replacement runs:
//   key.gpg        the OLD key (password: old password) until the very end
//   key-next.gpg   "s3vault-rotation-v1\nnew:<new key>\nold:<old key>\n", password: NEW password.
//                  Written first, so a crash never loses the new key; holds the old key too, so the
//                  new password alone can resume. Deleted when done.
//   rotation.json  marker: other devices drop their (old) key and refuse to unlock until it is gone
//   key-check      fingerprint of the current key (written at the end)
#include "util/compat.h"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>

#include "platform.h"
#include "util/fs.h"
#include "util/sha256.h"
#include "util/strings.h"
#include "util/subprocess.h"
#include "vault/vault.h"

namespace s3v {

static const char* kNextMagic = "s3vault-rotation-v1\n";
static const char* kCheckMagic = "s3vault-key-check-v1\n";
static const size_t kInMemoryMax = 64u << 20;  // larger objects go through ciphertext/plaintext temp files

std::string Vault::new_vault_key() { return to_hex(random_bytes(32)); }

std::string Vault::key_check_value(std::string_view key) {
    return std::string(kCheckMagic) + to_hex(hmac_sha256_raw(key, "s3vault-key-check")).substr(0, 32) + "\n";
}

static bool valid_key(std::string_view k) {
    if (k.size() != 64) return false;
    for (char c : k)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    return true;
}

// Objects re-encrypted by a replacement: encrypted files in the vault and in the vault trash.
static bool rotatable(const std::string& rel) {
    if (!ends_with(rel, ".gpg")) return false;
    if (starts_with(rel, ".s3vault/")) return starts_with(rel, ".s3vault/trash/");
    return true;
}

static std::string json_safe(std::string s) {
    for (auto& c : s)
        if (c == '"' || c == '\\' || static_cast<unsigned char>(c) < 0x20) c = '_';
    return s;
}

// Reads "name": "value" / "name": 123 from the small JSON we write ourselves.
static std::string json_field(const std::string& j, const char* name) {
    std::string pat = std::string("\"") + name + "\":";
    size_t p = j.find(pat);
    if (p == std::string::npos) return "";
    p += pat.size();
    while (p < j.size() && j[p] == ' ') p++;
    if (p < j.size() && j[p] == '"') {
        size_t e = j.find('"', p + 1);
        return e == std::string::npos ? "" : j.substr(p + 1, e - p - 1);
    }
    size_t e = p;
    while (e < j.size() && (isdigit(static_cast<unsigned char>(j[e])) || j[e] == '-')) e++;
    return j.substr(p, e - p);
}

static std::string shown_name(const std::string& rel) {
    std::string r = rel;
    if (ends_with(r, ".gpg")) r.resize(r.size() - 4);
    if (starts_with(r, ".s3vault/trash/")) {
        std::string rest = r.substr(strlen(".s3vault/trash/"));
        size_t sl = rest.find('/');
        return "Trash: " + (sl == std::string::npos ? rest : rest.substr(sl + 1));
    }
    return r;
}

// ---------------------------------------------------------------------------
// status

OpResult Vault::rotation_status(RotationStatus& out) {
    out = RotationStatus{};
    if (!s3_) return OpResult::fail("not connected");
    std::string body;
    S3Result r = s3_->get_string(prefix_ + ".s3vault/rotation.json", body, 1 << 16);
    if (r.not_found()) return OpResult::success();
    if (!r.ok()) return OpResult::fail("read rotation.json: " + r.describe());
    out.active = true;
    out.device = json_field(body, "device");
    out.started = atoll(json_field(body, "started").c_str());
    return OpResult::success();
}

OpResult Vault::rotation_stats(RotationStats& out) {
    out = RotationStats{};
    if (!s3_) return OpResult::fail("not connected");
    std::vector<ObjectInfo> objs;
    S3Result r = s3_->list_all(prefix_, objs);
    if (!r.ok()) return OpResult::fail("list: " + r.describe());
    for (auto& o : objs) {
        std::string rel = o.key.substr(prefix_.size());
        if (rotatable(rel)) {
            (starts_with(rel, ".s3vault/") ? out.trash_files : out.files)++;
            out.bytes += o.size;
        } else if (!starts_with(rel, ".s3vault/") && !ends_with(rel, "/")) {
            out.plain_files++;
        }
    }
    return OpResult::success();
}

std::string Vault::take_key_notice() {
    std::lock_guard<std::mutex> lk(mu_);
    std::string n;
    n.swap(key_notice_);
    return n;
}

// ---------------------------------------------------------------------------
// other devices: never keep writing with a key that is being (or was) replaced

void Vault::drop_key(const std::string& why) {
    keys_.lock();
    {
        std::lock_guard<std::mutex> lk(mu_);
        key_ct_.clear();
        check_etag_.clear();
        key_notice_ = why;
    }
    platform::keychain_erase(vault_account());
}

static const char* kBeingReplaced =
    "A vault key replacement is in progress or was paused. Encrypted files are paused until it is finished; "
    "then unlock with the new password.";
static const char* kReplaced = "The vault key was replaced on another device. Unlock with the new password.";

bool Vault::key_is_current(std::string_view key, std::string* why) {
    // Network errors count as "current": a flaky connection must not lock anyone out.
    std::string body;
    S3Result r = s3_->get_string(prefix_ + ".s3vault/key-check", body, 4096);
    if (r.ok() && body != key_check_value(key)) {
        if (why) *why = kReplaced;
        return false;
    }
    ObjectInfo oi;
    if (!rotating_self_ && s3_->head(prefix_ + ".s3vault/rotation.json", &oi).ok()) {
        if (why) *why = kBeingReplaced;
        return false;
    }
    return true;
}

void Vault::guard_key(bool rotation_marker, const std::string& check_etag) {
    if (rotating_self_ || !keys_.unlocked()) return;
    if (rotation_marker) {
        drop_key(kBeingReplaced);
        return;
    }
    if (check_etag.empty()) return;  // vault made before key-check existed
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (check_etag == check_etag_) return;
    }
    SecureString k = keys_.get();
    if (k.empty()) return;
    std::string body;
    S3Result r = s3_->get_string(prefix_ + ".s3vault/key-check", body, 4096);
    if (!r.ok()) return;
    if (body != key_check_value(k.view())) {
        drop_key(kReplaced);
        return;
    }
    std::lock_guard<std::mutex> lk(mu_);
    check_etag_ = check_etag;
}

// ---------------------------------------------------------------------------
// one object

static CryptoResult decrypt_file_to(const Gpg& gpg, const std::string& in, const std::string& out, std::string_view pass) {
    CryptoResult res;
    int fd = open(out.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) { res.detail = "cannot write " + out; return res; }
    FILE* f = fopen(in.c_str(), "rb");
    if (!f) { close(fd); res.detail = "cannot read " + in; return res; }
    Gpg::Decryptor d;
    std::string err;
    if (!gpg.start_decrypt(d, pass, fd, size_t(-1), &err)) {
        fclose(f);
        close(fd);
        res.detail = err;
        return res;
    }
    std::string buf(1 << 20, '\0');
    size_t n;
    while ((n = fread(&buf[0], 1, buf.size(), f)) > 0)
        if (!d.write(buf.data(), n)) break;  // gpg stopped early (wrong key): finish() says why
    fclose(f);
    res = d.finish();
    close(fd);
    return res;
}

static bool unreadable_status(CryptoStatus s) {
    return s == CryptoStatus::BadPassphrase || s == CryptoStatus::Tampered || s == CryptoStatus::NotEncrypted;
}

// Re-encrypts one object with the new key, conditional on the ETag that was read.
// old_etag "" afterwards: the object is gone. changed: it was replaced meanwhile (try again next pass).
OpResult Vault::rekey_object(const std::string& key, uint64_t size, const std::string& old_key, const std::string& new_key,
                             bool& already_new, bool& unreadable, bool& changed, std::string& old_etag,
                             std::string& new_etag) {
    already_new = unreadable = changed = false;
    old_etag.clear();
    new_etag.clear();
    Conditions c;
    S3Result put;

    if (size <= kInMemoryMax) {
        std::string ct;
        S3Result g = s3_->get(key, [&](const char* p, size_t n) {
            if (ct.size() + n > kInMemoryMax + (1 << 20)) return false;
            ct.append(p, n);
            return true;
        }, &old_etag);
        if (g.not_found()) { old_etag.clear(); return OpResult::success(); }
        if (!g.ok()) return OpResult::fail("download " + key + ": " + g.describe());
        std::string plain;
        CryptoResult d = gpg_.decrypt_string(ct, plain, old_key);
        if (!d.ok()) {
            wipe(plain);
            std::string probe;
            CryptoResult d2 = gpg_.decrypt_string(ct, probe, new_key);
            wipe(probe);
            if (d2.ok()) { already_new = true; return OpResult::success(); }
            if (unreadable_status(d.status)) { unreadable = true; return OpResult::success(); }
            return OpResult::fail("decrypt " + key + ": " + d.detail);
        }
        std::string ct2;
        CryptoResult e = gpg_.encrypt_string(plain, ct2, new_key);
        wipe(plain);
        if (!e.ok()) return OpResult::fail("encrypt " + key + ": " + e.detail);
        c.if_match = old_etag;
        put = s3_->put_string(key, ct2, c);
    } else {
        std::string base = staging_dir() + "/" + to_hex(random_bytes(8));
        std::string ct_in = base + ".in.gpg", plain = base + ".plain", ct_out = base + ".out.gpg";
        auto cleanup = [&] {
            unlink(ct_in.c_str());
            secure_unlink(plain);
            unlink(ct_out.c_str());
        };
        int fd = open(ct_in.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) return OpResult::fail("cannot write " + ct_in);
        S3Result g = s3_->get(key, [&](const char* p, size_t n) { return write_all_fd(fd, p, n); }, &old_etag);
        close(fd);
        if (g.not_found()) { cleanup(); old_etag.clear(); return OpResult::success(); }
        if (!g.ok()) { cleanup(); return OpResult::fail("download " + key + ": " + g.describe()); }
        CryptoResult d = decrypt_file_to(gpg_, ct_in, plain, old_key);
        if (!d.ok()) {
            secure_unlink(plain);
            CryptoResult d2 = decrypt_file_to(gpg_, ct_in, plain, new_key);
            cleanup();
            if (d2.ok()) { already_new = true; return OpResult::success(); }
            if (unreadable_status(d.status)) { unreadable = true; return OpResult::success(); }
            return OpResult::fail("decrypt " + key + ": " + d.detail);
        }
        std::string logical = key.substr(0, key.size() - 4);
        CryptoResult e = gpg_.encrypt_file(plain, ct_out, new_key, !Gpg::is_compressed_ext(path_ext_lower(logical)));
        secure_unlink(plain);
        if (!e.ok()) { cleanup(); return OpResult::fail("encrypt " + key + ": " + e.detail); }
        c.if_match = old_etag;
        put = s3_->put_file(key, ct_out, c);
        cleanup();
    }
    if (put.precondition_failed()) { changed = true; return OpResult::success(); }
    if (!put.ok()) return OpResult::fail("upload " + key + ": " + put.describe());
    new_etag = put.etag;
    return OpResult::success();
}

// ---------------------------------------------------------------------------
// the whole vault

static OpResult rotating_fail(const std::string& e) {
    OpResult f = OpResult::fail(e);
    f.rotating = true;
    return f;
}

OpResult Vault::run_rotation(const std::string& old_key, const std::string& new_key, const std::string& new_password,
                             const std::function<void(const RotationProgress&)>& progress,
                             const std::atomic<bool>* cancel) {
    RotationProgress pr;
    auto report = [&] { if (progress) progress(pr); };

    // Tracked-folder rows that point at an object: their base ETag follows the re-encrypted object, so sync
    // does not download files whose content did not change.
    struct Ref { int root; FileRow row; };
    std::map<std::string, std::vector<Ref>> refs;
    for (auto& root : db_.roots())
        for (auto& [rel, row] : db_.files(root.id))
            if (!row.remote_key.empty()) refs[row.remote_key].push_back({root.id, row});

    std::map<std::string, std::string> settled;  // object key → ETag known to need nothing more
    for (int pass = 1;; pass++) {
        if (pass > 6) return rotating_fail("Files kept changing on the server while they were re-encrypted. Resume to finish.");
        std::vector<ObjectInfo> objs;
        S3Result l = s3_->list_all(prefix_, objs);
        if (!l.ok()) return rotating_fail("list: " + l.describe());
        std::vector<ObjectInfo> todo;
        for (auto& o : objs) {
            if (!rotatable(o.key.substr(prefix_.size()))) continue;
            auto it = settled.find(o.key);
            if (it != settled.end() && it->second == o.etag) continue;
            todo.push_back(o);
        }
        if (todo.empty()) break;
        pr.pass = pass;
        pr.total += int(todo.size());
        for (auto& o : todo) pr.bytes_total += o.size;
        for (auto& o : todo) {
            if (cancel && *cancel) {
                OpResult f = rotating_fail("Paused. Resume with the new password to finish replacing the key.");
                f.paused = true;
                return f;
            }
            pr.current = shown_name(o.key.substr(prefix_.size()));
            report();
            bool already = false, unreadable = false, changed = false;
            std::string oe, ne;
            OpResult r = rekey_object(o.key, o.size, old_key, new_key, already, unreadable, changed, oe, ne);
            if (!r.ok) {
                // Ctrl-C in a terminal also interrupts the gpg child: that is a pause, not a failure.
                if (cancel && *cancel) {
                    OpResult f = rotating_fail("Paused. Resume with the new password to finish replacing the key.");
                    f.paused = true;
                    return f;
                }
                r.rotating = true;
                return r;
            }
            pr.done++;
            pr.bytes_done += o.size;
            if (oe.empty() || changed) continue;  // deleted, or replaced meanwhile: the next listing decides
            if (unreadable) { pr.unreadable++; settled[o.key] = oe; continue; }
            if (already) { pr.already_new++; settled[o.key] = oe; continue; }
            settled[o.key] = ne;
            auto rf = refs.find(o.key);
            if (rf != refs.end())
                for (auto& ref : rf->second)
                    if (ref.row.base_etag == oe) {
                        ref.row.base_etag = ne;
                        db_.upsert_file(ref.root, ref.row);
                    }
        }
    }

    // Every object is on the new key: make it the vault key.
    pr.finishing = true;
    pr.current.clear();
    report();
    std::string payload = std::string(key_magic()) + new_key + "\n";
    std::string ct;
    CryptoResult e = gpg_.encrypt_string(payload, ct, new_password, /*strong_s2k=*/true);
    wipe(payload);
    if (!e.ok()) return rotating_fail("gpg: " + e.detail);
    ObjectInfo ki;
    S3Result h = s3_->head(prefix_ + ".s3vault/key.gpg", &ki);
    Conditions c;
    if (h.ok()) c.if_match = ki.etag;
    else if (h.not_found()) c.if_none_match = true;
    else return rotating_fail("read key.gpg: " + h.describe());
    S3Result w = s3_->put_string(prefix_ + ".s3vault/key.gpg", ct, c);
    if (!w.ok()) return rotating_fail("write key.gpg: " + w.describe());
    S3Result kc = s3_->put_string(prefix_ + ".s3vault/key-check", key_check_value(new_key));
    if (!kc.ok()) return rotating_fail("write key-check: " + kc.describe());
    S3Result dm = s3_->del(prefix_ + ".s3vault/rotation.json");
    if (!dm.ok() && !dm.not_found()) return rotating_fail("remove rotation.json: " + dm.describe());
    s3_->del(prefix_ + ".s3vault/key-next.gpg");  // holds the old key: best effort, also cleaned up on resume

    keys_.set(new_key);
    {
        std::lock_guard<std::mutex> lk(mu_);
        key_ct_ = ct;
        check_etag_ = kc.etag;
        key_notice_.clear();
    }
    has_key_ = true;
    if (keys_.mode() == PassCache::Mode::Keychain && cfg_.security.keychain_days > 0)
        platform::keychain_store(vault_account(), new_key,
                                 int64_t(time(nullptr)) + int64_t(cfg_.security.keychain_days) * 86400);
    else
        platform::keychain_erase(vault_account());
    pr.finishing = false;
    report();
    refresh();
    return OpResult::success();
}

namespace {
struct ClearOnExit {
    std::atomic<bool>& flag;
    ~ClearOnExit() { flag = false; }
};
}  // namespace

OpResult Vault::rotate_key(const std::string& old_password, const std::string& new_password, const std::string& new_key,
                           const std::function<void(const RotationProgress&)>& progress,
                           const std::atomic<bool>* cancel) {
    if (!s3_) return OpResult::fail("not connected");
    if (!gpg_.available()) return OpResult::fail("gpg not found (deps.gpg)");
    if (!valid_key(new_key)) return OpResult::fail("invalid new key");
    if (new_password.empty()) return OpResult::fail("choose a new password");
    if (old_password == new_password) return OpResult::fail("The new password must be different from the current one.");
    RotationStatus rs;
    OpResult st = rotation_status(rs);
    if (!st.ok) return st;
    if (rs.active)
        return rotating_fail("A key replacement started on " + (rs.device.empty() ? std::string("another device") : rs.device) +
                             " is not finished. Resume it with its new password.");

    std::string cur;
    S3Result r = s3_->get_string(prefix_ + ".s3vault/key.gpg", cur, 1 << 20);
    if (r.not_found()) return OpResult::fail("this vault has no password yet (set one first)");
    if (!r.ok()) return OpResult::fail("read key.gpg: " + r.describe());
    std::string vk;
    CryptoResult d = gpg_.decrypt_string(cur, vk, old_password, 4096);
    if (d.status == CryptoStatus::BadPassphrase) {
        OpResult f = OpResult::fail("wrong current password");
        f.bad_key = true;
        return f;
    }
    if (!d.ok() || !starts_with(vk, key_magic())) return OpResult::fail("cannot read key.gpg: " + d.detail);
    std::string old_key = trim(vk.substr(strlen(key_magic())));
    wipe(vk);
    if (old_key == new_key) { wipe(old_key); return OpResult::fail("the new key equals the old key"); }

    rotating_self_ = true;
    ClearOnExit reset{rotating_self_};
    // 1. The new key, before anything is re-encrypted with it.
    std::string payload = std::string(kNextMagic) + "new:" + new_key + "\nold:" + old_key + "\n";
    std::string next;
    CryptoResult e = gpg_.encrypt_string(payload, next, new_password, /*strong_s2k=*/true);
    wipe(payload);
    if (!e.ok()) { wipe(old_key); return OpResult::fail("gpg: " + e.detail); }
    S3Result wn = s3_->put_string(prefix_ + ".s3vault/key-next.gpg", next);
    if (!wn.ok()) { wipe(old_key); return OpResult::fail("write key-next.gpg: " + wn.describe()); }
    // 2. The marker: other devices stop using the old key.
    char json[512];
    snprintf(json, sizeof json, "{\n  \"format\": 1,\n  \"started\": %lld,\n  \"device\": \"%s\"\n}\n",
             static_cast<long long>(time(nullptr)), json_safe(cfg_.device()).c_str());
    Conditions c;
    c.if_none_match = true;
    S3Result wm = s3_->put_string(prefix_ + ".s3vault/rotation.json", json, c);
    if (!wm.ok()) {
        wipe(old_key);
        return wm.precondition_failed() ? rotating_fail("Another device started replacing the key just now.")
                                        : OpResult::fail("write rotation.json: " + wm.describe());
    }
    // 3. Everything else.
    OpResult res = run_rotation(old_key, new_key, new_password, progress, cancel);
    wipe(old_key);
    return res;
}

OpResult Vault::resume_rotation(const std::string& new_password, const std::function<void(const RotationProgress&)>& progress,
                                const std::atomic<bool>* cancel) {
    if (!s3_) return OpResult::fail("not connected");
    if (!gpg_.available()) return OpResult::fail("gpg not found (deps.gpg)");
    RotationStatus rs;
    OpResult st = rotation_status(rs);
    if (!st.ok) return st;
    std::string next;
    S3Result r = s3_->get_string(prefix_ + ".s3vault/key-next.gpg", next, 1 << 20);
    if (!rs.active) {
        // A leftover from a run that stopped before the marker was written (nothing was re-encrypted), or
        // from a finished run whose last clean-up step failed. It holds an old key: remove it.
        if (r.ok()) s3_->del(prefix_ + ".s3vault/key-next.gpg");
        return OpResult::fail("There is no key replacement to resume.");
    }
    if (r.not_found())
        return rotating_fail(".s3vault/key-next.gpg is missing, so the replacement can't be resumed. Restore it from a "
                             "backup of the vault, then try again.");
    if (!r.ok()) return rotating_fail("read key-next.gpg: " + r.describe());
    std::string plain;
    CryptoResult d = gpg_.decrypt_string(next, plain, new_password, 4096);
    if (d.status == CryptoStatus::BadPassphrase) {
        OpResult f = rotating_fail("Wrong password. Use the NEW password chosen when the replacement started.");
        f.bad_key = true;
        return f;
    }
    if (!d.ok() || !starts_with(plain, kNextMagic)) return rotating_fail("cannot read key-next.gpg: " + d.detail);
    std::string new_key, old_key;
    for (auto& line : split(plain.substr(strlen(kNextMagic)), '\n')) {
        if (starts_with(line, "new:")) new_key = trim(line.substr(4));
        else if (starts_with(line, "old:")) old_key = trim(line.substr(4));
    }
    wipe(plain);
    if (!valid_key(new_key) || !valid_key(old_key)) return rotating_fail("key-next.gpg is damaged");
    rotating_self_ = true;
    ClearOnExit reset{rotating_self_};
    OpResult res = run_rotation(old_key, new_key, new_password, progress, cancel);
    wipe(old_key);
    wipe(new_key);
    return res;
}

}  // namespace s3v
