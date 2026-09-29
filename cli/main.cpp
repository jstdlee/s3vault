// s3vault-cli — headless client: setup, vault init/unlock, tracked folders, sync, vault file operations.
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "config/config.h"
#include "crypto/gpg.h"
#include "index/db.h"
#include "platform.h"
#include "preview/preview.h"
#include "secret/strength.h"
#include "store/curl_dl.h"
#include "sync/engine.h"
#include "util/fs.h"
#include "util/secure.h"
#include "util/sha256.h"
#include "util/strings.h"
#include "util/subprocess.h"
#include "vault/vault.h"

using namespace s3v;

namespace {

const char* kUsage = R"(s3vault-cli — sync files with S3-compatible storage (AWS S3, Cloudflare R2, MinIO, B2, Wasabi)

Setup
  config show | get <key> | set <key> <value>   e.g. set storage.bucket my-bucket
  secret set                    read the S3 secret key from stdin into the keychain
  deps                          check gpg, pdftoppm, editor, keychain
  probe [--multipart]           test the storage: auth, conditional writes, copy, multipart

Vault
  init [--no-password]          create the vault (asks for a password)
  passwd                        set or change the vault password
  lock                          forget a remembered vault key (keychain mode)
  gen-password                  print a strong random password

Tracked folders
  roots                                          list
  add-root <dir> [--remote P] [--direction two-way|upload-only|download-only] [--plain]
  rm-root <id> | pause <id> | resume <id>
  sync                                           one pass over all tracked folders
  watch                                          keep syncing (file watcher + polling) until Ctrl-C

Vault files (paths are inside the vault)
  ls [dir] [--sort name|type|size|modified] [--reverse] [-r]
  put <local-file> [vault-path] [--plain|--encrypt] [--overwrite]
  get <vault-path> [local-dest]
  cat <vault-path>              decrypt to stdout (text, ≤ preview.text_max_mb)
  mkdir <dir> | mv <from> <to> | rm <path>
  trash | restore <n> | purge [days]
  conflicts | resolve <id> keep-local|keep-remote|keep-both|keep-newest

Environment
  S3VAULT_HOME         config+data dir (default ~/.config/s3vault, ~/.local/share/s3vault)
  S3VAULT_SECRET_KEY   S3 secret key (instead of the keychain)
  S3VAULT_PASSWORD     vault password (scripts/tests; otherwise prompted)
)";

struct Ctx {
    Config cfg;
    Db db;
    std::unique_ptr<Vault> vault;
    std::unique_ptr<Engine> engine;
};

std::string read_password(const std::string& prompt) {
    if (const char* p = getenv("S3VAULT_PASSWORD"); p && *p) return p;
    fprintf(stderr, "%s", prompt.c_str());
    termios old{};
    bool tty = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old) == 0;
    if (tty) {
        termios t = old;
        t.c_lflag &= ~tcflag_t(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &t);
    }
    std::string pw;
    std::getline(std::cin, pw);
    if (tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        fprintf(stderr, "\n");
    }
    return pw;
}

std::string ask_new_password(int min_len) {
    for (;;) {
        std::string a = read_password("New vault password: ");
        Strength s = check_password(a, min_len);
        if (!s.acceptable) {
            fprintf(stderr, "Password too weak (score %d/4):\n", s.score);
            for (auto& p : s.problems) fprintf(stderr, "  - %s\n", p.c_str());
            fprintf(stderr, "Suggestion: %s\n", generate_password().c_str());
            wipe(a);
            if (getenv("S3VAULT_PASSWORD")) exit(2);
            continue;
        }
        if (getenv("S3VAULT_PASSWORD")) return a;
        std::string b = read_password("Repeat password: ");
        if (a != b) {
            fprintf(stderr, "Passwords do not match.\n");
            wipe(a);
            wipe(b);
            continue;
        }
        wipe(b);
        return a;
    }
}

int die(const std::string& m) {
    fprintf(stderr, "error: %s\n", m.c_str());
    return 1;
}

bool open_ctx(Ctx& c, bool connect = true) {
    c.cfg.load(config_path());
    std::string err;
    if (!c.db.open(data_dir() + "/index.db", &err)) {
        die("index: " + err);
        return false;
    }
    c.vault = std::make_unique<Vault>(c.cfg, c.db);
    c.engine = std::make_unique<Engine>(c.cfg, c.db, *c.vault);
    if (!connect) return true;
    if (!c.vault->connect(err)) {
        die(err + " (see: s3vault-cli config / secret set)");
        return false;
    }
    return true;
}

// Unlocks when the vault has a key: keychain → S3VAULT_PASSWORD → prompt.
bool ensure_unlocked(Ctx& c, bool required) {
    bool exists = false;
    OpResult r = c.vault->load_info(exists);
    if (!r.ok) { die(r.error); return false; }
    if (!exists) { die("no vault at " + c.cfg.storage.bucket + "/" + c.vault->prefix() + " (run: s3vault-cli init)"); return false; }
    if (!c.vault->has_key()) {
        if (required) { die("this vault has no password yet (run: s3vault-cli passwd)"); return false; }
        return true;
    }
    if (c.vault->try_unlock_from_keychain()) return true;
    for (int i = 0; i < 3; i++) {
        std::string pw = read_password("Vault password: ");
        OpResult u = c.vault->unlock(pw);
        wipe(pw);
        if (u.ok) return true;
        fprintf(stderr, "%s\n", u.error.c_str());
        if (!u.bad_key || getenv("S3VAULT_PASSWORD")) return false;
    }
    return false;
}

std::string flag(std::vector<std::string>& a, const std::string& name, const std::string& def = "") {
    for (size_t i = 0; i + 1 < a.size(); i++)
        if (a[i] == name) {
            std::string v = a[i + 1];
            a.erase(a.begin() + long(i), a.begin() + long(i) + 2);
            return v;
        }
    return def;
}

bool has(std::vector<std::string>& a, const std::string& name) {
    auto it = std::find(a.begin(), a.end(), name);
    if (it == a.end()) return false;
    a.erase(it);
    return true;
}

std::string norm(std::string p) {
    while (!p.empty() && p.front() == '/') p.erase(0, 1);
    while (!p.empty() && p.back() == '/') p.pop_back();
    return p;
}

const RemoteEntry* find_entry(const std::vector<RemoteEntry>& all, const std::string& logical) {
    for (auto& e : all)
        if (!e.dir_marker && e.logical == logical) return &e;
    return nullptr;
}

int cmd_probe(Ctx& c, bool multipart) {
    S3Client& s = c.vault->s3();
    std::string key = c.vault->prefix() + ".s3vault/probe/" + c.cfg.device() + "-" + to_hex(random_bytes(4));
    int fails = 0;
    auto check = [&](const char* what, bool ok, const std::string& detail = "") {
        printf("  %-40s %s %s\n", what, ok ? "ok" : "FAIL", detail.c_str());
        if (!ok) fails++;
    };
    S3Result r = s.put_string(key, "probe-1");
    check("PUT (auth, endpoint)", r.ok(), r.ok() ? "" : r.describe());
    if (!r.ok()) return 1;
    std::string etag1 = r.etag;
    Conditions inm;
    inm.if_none_match = true;
    r = s.put_string(key, "probe-2", inm);
    check("PUT If-None-Match: * on existing → 412", r.http == 412, r.http == 412 ? "" : r.describe());
    Conditions stale;
    stale.if_match = "00000000000000000000000000000000";
    r = s.put_string(key, "probe-3", stale);
    check("PUT If-Match: <stale> → 412", r.http == 412, r.http == 412 ? "" : r.describe());
    Conditions good;
    good.if_match = etag1;
    r = s.put_string(key, "probe-4", good);
    check("PUT If-Match: <current> → 200", r.ok(), r.ok() ? "" : r.describe());
    S3Result cp = s.copy(key, key + ".copy");
    check("CopyObject", cp.ok(), cp.ok() ? "" : cp.describe());
    std::vector<ObjectInfo> objs;
    S3Result ls = s.list_all(key, objs);
    check("ListObjectsV2", ls.ok() && objs.size() == 2, ls.ok() ? std::to_string(objs.size()) + " objects" : ls.describe());
    std::string body;
    S3Result g = s.get_string(key, body);
    check("GET", g.ok() && body == "probe-4");
    if (multipart) {
        std::string tmp = c.vault->staging_dir() + "/probe.bin";
        write_file_atomic(tmp, random_bytes(17u << 20), 0600);
        uint64_t old = s.multipart_threshold;
        s.multipart_threshold = 8u << 20;
        S3Result m = s.put_file(key + ".mp", tmp);
        s.multipart_threshold = old;
        check("Multipart upload (17 MiB, 2 parts)", m.ok(), m.ok() ? "" : m.describe());
        ObjectInfo oi;
        S3Result h = s.head(key + ".mp", &oi);
        check("  size after multipart", h.ok() && oi.size == (17u << 20));
        s.del(key + ".mp");
        unlink(tmp.c_str());
    }
    s.del(key);
    s.del(key + ".copy");
    printf(fails ? "%d check(s) failed: conditional writes may not be safe on this provider.\n"
                 : "All checks passed.\n", fails);
    return fails ? 1 : 0;
}

void print_entries(std::vector<RemoteEntry> es, const std::string& sort, bool rev) {
    std::sort(es.begin(), es.end(), [&](const RemoteEntry& a, const RemoteEntry& b) {
        if (a.dir_marker != b.dir_marker) return a.dir_marker;  // folders first
        int c = 0;
        if (sort == "size") c = a.size < b.size ? -1 : a.size > b.size ? 1 : 0;
        else if (sort == "modified") c = a.mtime < b.mtime ? -1 : a.mtime > b.mtime ? 1 : 0;
        else if (sort == "type") c = strcmp(file_type_label(a.logical), file_type_label(b.logical));
        if (c == 0) c = strcasecmp(a.logical.c_str(), b.logical.c_str());
        return rev ? c > 0 : c < 0;
    });
    for (auto& e : es) {
        if (e.dir_marker)
            printf("%-10s %10s  %-16s  %s/\n", "Folder", "", format_local_time(e.mtime).c_str(), e.logical.c_str());
        else
            printf("%-10s %10s  %-16s  %s%s\n", file_type_label(e.logical), human_size(e.size).c_str(),
                   format_local_time(e.mtime).c_str(), e.logical.c_str(), e.encrypted ? "  [encrypted]" : "");
    }
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> a(argv + 1, argv + argc);
    if (std::string h = flag(a, "--home"); !h.empty()) setenv("S3VAULT_HOME", h.c_str(), 1);
    if (a.empty() || a[0] == "-h" || a[0] == "--help" || a[0] == "help") {
        printf("%s", kUsage);
        return a.empty() ? 1 : 0;
    }
    platform::install_exit_cleanup();
    platform::cleanup_stale_tmp();
    curl_api();  // curl_global_init before `watch` starts the engine threads
    std::string cmd = a[0];
    a.erase(a.begin());
    Ctx c;

    // ---- commands that do not need the network ----
    if (cmd == "config") {
        c.cfg.load(config_path());
        std::string sub = a.empty() ? "show" : a[0];
        if (sub == "show") {
            printf("# %s\n", config_path().c_str());
            for (auto& [k, v] : c.cfg.dump()) printf("%s = %s\n", k.c_str(), v.c_str());
            return 0;
        }
        if (sub == "get" && a.size() >= 2) {
            auto m = c.cfg.dump();
            if (!m.count(a[1])) return die("unknown key " + a[1]);
            printf("%s\n", m[a[1]].c_str());
            return 0;
        }
        if (sub == "set" && a.size() >= 3) {
            if (!c.cfg.set(a[1], a[2])) return die("unknown key " + a[1]);
            if (!c.cfg.save(config_path())) return die("cannot write " + config_path());
            return 0;
        }
        return die("usage: config show | get <key> | set <key> <value>");
    }
    if (cmd == "secret") {
        c.cfg.load(config_path());
        if (a.empty() || a[0] != "set") return die("usage: secret set  (reads the secret from stdin)");
        if (c.cfg.storage.access_key_id.empty()) return die("set storage.access_key_id first");
        std::string s = read_password("S3 secret access key: ");
        s = trim(s);
        bool ok = platform::keychain_store(Vault::secret_account(c.cfg.storage), s);
        wipe(s);
        if (!ok) return die("keychain not available; use the S3VAULT_SECRET_KEY environment variable instead");
        printf("Stored in the keychain.\n");
        return 0;
    }
    if (cmd == "gen-password") {
        printf("%s\n", generate_password().c_str());
        return 0;
    }
    if (cmd == "deps") {
        c.cfg.load(config_path());
        Gpg g(c.cfg.deps.gpg);
        printf("gpg        %s\n", g.available() ? (g.exe() + " " + g.version()).c_str()
                                                 : ("MISSING " + g.version()).c_str());
        std::string p = find_executable(c.cfg.deps.pdftoppm == "auto" ? "pdftoppm" : c.cfg.deps.pdftoppm);
        printf("pdftoppm   %s\n", p.empty() ? "missing (PDF preview disabled; install poppler-utils)" : p.c_str());
        printf("pdfinfo    %s\n", find_executable("pdfinfo").empty() ? "missing" : find_executable("pdfinfo").c_str());
        printf("keychain   %s\n", platform::keychain_available() ? "Secret Service (libsecret)" : "not available");
        printf("tmp dir    %s (%s)\n", platform::session_tmp_dir().c_str(),
               platform::session_tmp_in_ram() ? "RAM/tmpfs" : "DISK — files are overwritten before deletion");
        return g.available() ? 0 : 1;
    }

    if (!open_ctx(c, cmd != "roots" && cmd != "rm-root" && cmd != "pause" && cmd != "resume" && cmd != "conflicts"))
        return 1;
    Vault& v = *c.vault;
    Engine& eng = *c.engine;

    if (cmd == "probe") return cmd_probe(c, has(a, "--multipart"));

    if (cmd == "init") {
        bool nopw = has(a, "--no-password");
        std::string pw = nopw ? "" : ask_new_password(c.cfg.security.min_length);
        OpResult r = v.init(pw);
        wipe(pw);
        if (!r.ok) return die(r.error);
        printf("Vault created at %s/%s%s\n", c.cfg.storage.bucket.c_str(), v.prefix().c_str(),
               nopw ? " (no password: only plain files until you run passwd)" : "");
        return 0;
    }
    if (cmd == "passwd") {
        bool exists = false;
        OpResult li = v.load_info(exists);
        if (!li.ok || !exists) return die(li.ok ? "no vault here (run init)" : li.error);
        bool had = v.has_key();
        std::string old;
        if (had) {
            const char* o = getenv("S3VAULT_OLD_PASSWORD");  // scripts/tests
            old = o ? o : read_password("Current password: ");
        }
        std::string nw = ask_new_password(c.cfg.security.min_length);
        OpResult r = v.set_password(old, nw);
        wipe(old);
        wipe(nw);
        if (!r.ok) return die(r.error);
        printf("Password %s. Files did not need re-encryption.\n", had ? "changed" : "set");
        return 0;
    }
    if (cmd == "lock") {
        v.lock();
        printf("Locked.\n");
        return 0;
    }

    if (cmd == "roots") {
        for (auto& r : c.db.roots())
            printf("%d  %s  →  /%s  [%s%s%s]\n", r.id, r.local_path.c_str(), r.remote_prefix.c_str(), r.direction.c_str(),
                   r.encrypt ? ", encrypt new files" : ", plain", r.paused ? ", PAUSED" : "");
        return 0;
    }
    if (cmd == "add-root") {
        if (a.empty()) return die("usage: add-root <dir> [--remote P] [--direction D] [--plain]");
        std::string remote = flag(a, "--remote");
        std::string dir = flag(a, "--direction", "two-way");
        bool plain = has(a, "--plain");
        if (remote.empty()) remote = path_basename(a[0]);
        std::string err;
        int id = eng.add_root(a[0], norm(remote), dir, !plain, err);
        if (!id) return die(err);
        printf("Tracking %s as /%s (root %d). Run: s3vault-cli sync\n", a[0].c_str(), norm(remote).c_str(), id);
        return 0;
    }
    if (cmd == "rm-root" || cmd == "pause" || cmd == "resume") {
        if (a.empty()) return die("usage: " + cmd + " <id>");
        int id = atoi(a[0].c_str());
        for (auto r : c.db.roots()) {
            if (r.id != id) continue;
            if (cmd == "rm-root") c.db.remove_root(id);
            else { r.paused = cmd == "pause"; c.db.update_root(r); }
            printf("ok\n");
            return 0;
        }
        return die("no root " + a[0]);
    }
    if (cmd == "conflicts") {
        auto roots = c.db.roots();
        for (auto& k : c.db.conflicts()) {
            std::string rp;
            for (auto& r : roots) if (r.id == k.root_id) rp = r.local_path;
            printf("%lld  %-15s %s/%s\n      local:  %s\n      remote: %s\n", static_cast<long long>(k.id),
                   k.kind.c_str(), rp.c_str(), k.rel.c_str(),
                   k.local_exists ? (human_size(k.local_size) + ", " + format_local_time(k.local_mtime) + ", " + k.local_hash.substr(0, 10)).c_str() : "deleted",
                   k.remote_exists ? (human_size(k.remote_size) + ", " + format_local_time(k.remote_mtime)).c_str() : "deleted");
        }
        return 0;
    }
    if (cmd == "resolve") {
        if (a.size() < 2) return die("usage: resolve <id> keep-local|keep-remote|keep-both|keep-newest");
        std::map<std::string, Resolution> m = {{"keep-local", Resolution::KeepLocal}, {"keep-remote", Resolution::KeepRemote},
                                               {"keep-both", Resolution::KeepBoth}, {"keep-newest", Resolution::KeepNewest}};
        if (!m.count(a[1])) return die("unknown resolution " + a[1]);
        if (!ensure_unlocked(c, false)) return 1;
        std::vector<int64_t> ids;
        if (a[0] == "all") for (auto& k : c.db.conflicts()) ids.push_back(k.id);
        else ids.push_back(atoll(a[0].c_str()));
        int fails = 0;
        for (auto id : ids) {
            OpResult r = eng.resolve(id, m[a[1]]);
            if (!r.ok) { fprintf(stderr, "conflict %lld: %s\n", static_cast<long long>(id), r.error.c_str()); fails++; }
        }
        v.refresh();
        printf("%zu resolved, %d failed\n", ids.size() - size_t(fails), fails);
        return fails ? 1 : 0;
    }
    if (cmd == "sync") {
        if (!ensure_unlocked(c, false)) return 1;
        SyncReport r = eng.sync_all(true);
        for (auto& m : r.messages) printf("  %s\n", m.c_str());
        printf("%s\n", r.summary().c_str());
        return r.errors ? 1 : 0;
    }
    if (cmd == "watch") {
        if (!ensure_unlocked(c, false)) return 1;
        eng.on_synced = [&] { printf("[%s] %s\n", format_local_time(time(nullptr)).c_str(), eng.last_summary().c_str()); fflush(stdout); };
        eng.start();
        printf("Watching (Ctrl-C to stop)…\n");
        for (;;) pause();
    }

    // ---- vault file operations ----
    if (cmd == "ls") {
        std::string sort = flag(a, "--sort", "name");
        bool rev = has(a, "--reverse");
        bool rec = has(a, "-r");
        std::string dir = a.empty() ? "" : norm(a[0]);
        std::vector<RemoteEntry> all;
        OpResult r = v.refresh(&all);
        if (!r.ok) return die(r.error);
        std::vector<RemoteEntry> shown;
        std::map<std::string, RemoteEntry> implied;
        std::string pfx = dir.empty() ? "" : dir + "/";
        for (auto& e : all) {
            if (!starts_with(e.logical, pfx) || e.logical == dir) continue;
            std::string rest = e.logical.substr(pfx.size());
            size_t sl = rest.find('/');
            if (rec || sl == std::string::npos) {
                shown.push_back(e);
            } else {
                // Folder implied by a deeper key.
                RemoteEntry d;
                d.dir_marker = true;
                d.logical = pfx + rest.substr(0, sl);
                d.mtime = std::max(implied[d.logical].mtime, e.mtime);
                implied[d.logical] = d;
            }
        }
        for (auto& e : shown) implied.erase(e.logical);
        for (auto& [k, d] : implied) shown.push_back(d);
        print_entries(shown, sort, rev);
        return 0;
    }
    if (cmd == "put") {
        bool plain = has(a, "--plain"), enc = has(a, "--encrypt"), over = has(a, "--overwrite");
        if (a.empty()) return die("usage: put <local-file> [vault-path]");
        std::string dest = a.size() >= 2 ? norm(a[1]) : path_basename(a[0]);
        if (a.size() >= 2 && ends_with(a[1], "/")) dest = norm(a[1]) + "/" + path_basename(a[0]);
        bool vault_exists = false;
        if (OpResult li = v.load_info(vault_exists); !li.ok || !vault_exists) return die(li.ok ? "no vault here (run init)" : li.error);
        // Encrypted by default once the vault has a password; *.gpg names are always encrypted.
        bool encrypt = enc || (!plain && v.has_key()) || ends_with(dest, ".gpg");
        if (encrypt && !ensure_unlocked(c, true)) return 1;
        std::vector<RemoteEntry> all;
        v.refresh(&all);
        Conditions cond;
        const RemoteEntry* ex = find_entry(all, dest);
        if (ex && !over) return die(dest + " already exists (use --overwrite)");
        if (ex) {
            cond.if_match = ex->etag;
            encrypt = ex->encrypted;
        } else {
            cond.if_none_match = true;
        }
        OpResult r = v.upload_file(a[0], ex ? ex->key : v.key_for(dest, encrypt), cond,
                                   [](uint64_t d, uint64_t t) { fprintf(stderr, "\r  %s / %s", human_size(d).c_str(), human_size(t).c_str()); });
        fprintf(stderr, "\n");
        if (!r.ok) return die(r.precondition_failed ? dest + " changed on the server meanwhile" : r.error);
        printf("uploaded %s%s\n", dest.c_str(), encrypt ? " (encrypted)" : "");
        return 0;
    }
    if (cmd == "get" || cmd == "cat") {
        if (a.empty()) return die("usage: " + cmd + " <vault-path>");
        std::vector<RemoteEntry> all;
        OpResult lr = v.refresh(&all);
        if (!lr.ok) return die(lr.error);
        const RemoteEntry* e = find_entry(all, norm(a[0]));
        if (!e) return die("not found: " + a[0]);
        if (e->encrypted && !ensure_unlocked(c, true)) return 1;
        if (cmd == "get") {
            std::string dest = a.size() >= 2 ? a[1] : path_basename(e->logical);
            if (stat_path(dest, true).is_dir) dest += "/" + path_basename(e->logical);
            OpResult r = v.download_to(e->key, dest);
            if (!r.ok) return die(r.error);
            printf("saved %s\n", dest.c_str());
            return 0;
        }
        {  // cat
            std::string out;
            OpResult r = load_preview_bytes(v, *e, PreviewLimits::from(c.cfg.preview).text_max, out);
            if (!r.ok) return die(r.error);
            fwrite(out.data(), 1, out.size(), stdout);
            wipe(out);
            return 0;
        }
        return 0;
    }
    if (cmd == "mkdir") {
        if (a.empty()) return die("usage: mkdir <dir>");
        OpResult r = v.mkdir(norm(a[0]));
        return r.ok ? 0 : die(r.error);
    }
    if (cmd == "mv") {
        if (a.size() < 2) return die("usage: mv <from> <to>");
        OpResult r = v.rename(norm(a[0]), norm(a[1]));
        return r.ok ? 0 : die(r.error);
    }
    if (cmd == "rm") {
        if (a.empty()) return die("usage: rm <path>");
        OpResult r = v.remove(norm(a[0]));
        if (!r.ok) return die(r.error);
        printf("moved to vault trash: %s\n", norm(a[0]).c_str());
        return 0;
    }
    if (cmd == "trash" || cmd == "restore") {
        OpResult err;
        auto t = v.trash_list(&err);
        if (!err.ok) return die(err.error);
        if (cmd == "trash") {
            for (size_t i = 0; i < t.size(); i++)
                printf("%3zu  %s  %10s  %s%s\n", i + 1, format_local_time(t[i].deleted_at).c_str(),
                       human_size(t[i].size).c_str(), t[i].logical.c_str(), t[i].encrypted ? "  [encrypted]" : "");
            return 0;
        }
        if (a.empty()) return die("usage: restore <n>  (see: trash)");
        size_t n = size_t(atoi(a[0].c_str()));
        if (n < 1 || n > t.size()) return die("no trash entry " + a[0]);
        OpResult r = v.restore(t[n - 1]);
        if (!r.ok) return die(r.error);
        printf("restored %s\n", t[n - 1].logical.c_str());
        return 0;
    }
    if (cmd == "purge") {
        int days = a.empty() ? c.cfg.sync.trash_days : atoi(a[0].c_str());
        int n = 0;
        OpResult r = v.purge_trash(days, &n);
        if (!r.ok) return die(r.error);
        printf("purged %d object(s) older than %d days\n", n, days);
        return 0;
    }
    fprintf(stderr, "unknown command: %s\n\n%s", cmd.c_str(), kUsage);
    return 1;
}
