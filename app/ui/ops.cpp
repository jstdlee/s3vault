// Vault operations started from the UI. They run on worker threads and report through the Transfers view,
// the activity log and toasts; the UI thread never waits on the network.
#include <dirent.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <ctime>
#include <mutex>
#include <thread>

#include "app.h"
#include "util/compat.h"
#include "platform.h"
#include "util/fs.h"
#include "util/secure.h"
#include "util/sha256.h"
#include "util/strings.h"

namespace s3v::ui {

static std::string join_logical(const std::string& dir, const std::string& name) {
    return dir.empty() ? name : dir + "/" + name;
}

void start_uploads(App& a, const std::vector<std::string>& files) {
    if (a.conn != App::Conn::Ready) {
        a.notify("Not connected", true);
        return;
    }
    a.pending_uploads = files;
    snprintf(a.text_buf, sizeof a.text_buf, "%s", a.cwd.c_str());
    a.upload_encrypt = a.vault_has_key;
    a.modal = "upload";
}

void choose_and_upload(App& a) {
    browse(a, BrowseMode::OpenMany, a.cwd.empty() ? "Upload to All Files" : "Upload to " + path_basename(a.cwd),
           [&a](std::vector<std::string> f) { start_uploads(a, f); });
}

void add_tracked_folder(App& a) {
    if (a.conn != App::Conn::Ready) {
        a.notify("Connect to your storage first", true);
        return;
    }
    browse(a, BrowseMode::Folder, "Choose a Folder to Keep in Sync", [&a](std::vector<std::string> d) {
        a.modal_arg = d[0];
        snprintf(a.text_buf, sizeof a.text_buf, "%s", path_basename(d[0]).c_str());
        a.upload_encrypt = a.vault_has_key;
        a.upload_on_exists = 0;  // reused as the direction index in the add-folder sheet
        a.modal = "add-root";
    });
}

void refresh_listing(App& a) {
    if (!a.vault) return;
    auto v = a.vault;
    a.run_job([&a, v] {
        OpResult r = v->refresh();
        a.post([&a, r] {
            a.tree_dirty = true;
            a.trash_dirty = true;
            if (!r.ok) a.notify(r.error, true);
        });
    });
    if (a.engine) a.engine->request_sync();
}

void test_storage(App& a) {
    if (!a.vault || !a.vault->connected()) return;
    a.probing = true;
    a.probe_report.clear();
    auto v = a.vault;
    a.run_job([&a, v] {
        std::string rep;
        S3Client& s = v->s3();
        std::string key = v->prefix() + ".s3vault/probe/" + to_hex(random_bytes(6));
        int fails = 0;
        auto line = [&](const char* what, bool ok, const std::string& d = "") {
            rep += std::string(ok ? "✓  " : "✗  ") + what + (d.empty() ? "" : " — " + d) + "\n";
            fails += !ok;
        };
        S3Result r = s.put_string(key, "1");
        line("Write", r.ok(), r.ok() ? "" : r.describe());
        if (r.ok()) {
            Conditions inm;
            inm.if_none_match = true;
            S3Result r2 = s.put_string(key, "2", inm);
            line("Safe create (If-None-Match)", r2.http == 412, r2.http == 412 ? "" : r2.describe());
            Conditions st;
            st.if_match = "0000";
            S3Result r3 = s.put_string(key, "3", st);
            line("Safe update (If-Match)", r3.http == 412, r3.http == 412 ? "" : r3.describe());
            S3Result c = s.copy(key, key + ".c");
            line("Server-side copy", c.ok(), c.ok() ? "" : c.describe());
            s.del(key);
            s.del(key + ".c");
        }
        rep = (fails ? "Some checks failed:\n" : "Everything works:\n") + rep;
        a.post([&a, rep] { a.probe_report = rep; a.probing = false; });
    });
}

void upload_files(App& a, std::vector<std::string> files, std::string dest_dir, bool encrypt, int on_exists) {
    auto v = a.vault;
    auto eng = a.engine;
    int workers = std::max(1, std::min(4, a.cfg.sync.concurrency));
    a.run_job([&a, v, eng, files, dest_dir, encrypt, on_exists, workers] {
        // Expand folders, keeping their structure under dest_dir.
        struct Item {
            std::string local, logical;
            uint64_t size = 0;
            int tid = 0;
        };
        std::vector<Item> items;
        std::function<void(const std::string&, const std::string&)> walk = [&](const std::string& p, const std::string& logical) {
            FileStat st = stat_path(p, true);
            if (st.is_file) {
                items.push_back({p, logical, st.size, 0});
            } else if (st.is_dir) {
                if (DIR* d = opendir(p.c_str())) {
                    while (dirent* e = readdir(d)) {
                        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
                        walk(p + "/" + e->d_name, logical + "/" + e->d_name);
                    }
                    closedir(d);
                }
            }
        };
        for (auto& f : files) {
            std::string p = f;
            while (p.size() > 1 && p.back() == '/') p.pop_back();
            walk(p, join_logical(dest_dir, path_basename(p)));
        }
        // Everything shows up in Transfers right away as "queued".
        for (auto& it : items) it.tid = eng->transfer_begin("upload", it.logical, it.size, true);
        eng->log("upload started: " + std::to_string(items.size()) + " file(s) → /" + dest_dir);
        std::vector<RemoteEntry> all;
        v->refresh(&all);
        std::map<std::string, RemoteEntry> by;
        for (auto& e : all)
            if (!e.dir_marker) by[e.logical] = e;
        std::atomic<int> ok{0}, skipped{0}, failed{0};
        std::mutex err_mu;
        std::string last_err;
        std::atomic<size_t> next{0};
        std::vector<std::thread> pool;
        for (int w = 0; w < workers; w++) {
            pool.emplace_back([&] {
                for (size_t k; (k = next++) < items.size();) {
                    Item& it = items[k];
                    bool enc = encrypt || ends_with(it.logical, ".gpg");
                    Conditions c;
                    std::string key, shown = it.logical;
                    auto ex = by.find(it.logical);
                    if (ex != by.end()) {
                        if (on_exists == 2) {
                            skipped++;
                            eng->transfer_end(it.tid);
                            eng->log("skipped (already exists): " + it.logical);
                            continue;
                        }
                        if (on_exists == 1) {
                            shown = Vault::conflict_name(it.logical, "uploaded");
                            key = v->key_for(shown, enc);
                            c.if_none_match = true;
                        } else {
                            key = ex->second.key;  // overwrite keeps the existing form
                            c.if_match = ex->second.etag;
                        }
                    } else {
                        key = v->key_for(it.logical, enc);
                        c.if_none_match = true;
                    }
                    eng->transfer_start(it.tid);
                    OpResult r = v->upload_file(it.local, key, c, [&](uint64_t d, uint64_t t) { eng->transfer_progress(it.tid, d, t); });
                    eng->transfer_end(it.tid);
                    if (r.ok) {
                        ok++;
                        eng->log("uploaded " + shown + (ends_with(key, ".gpg") ? " (encrypted)" : ""));
                    } else {
                        failed++;
                        eng->log("upload failed: " + it.logical + " (" + r.error + ")");
                        std::lock_guard<std::mutex> lk(err_mu);
                        last_err = r.error;
                    }
                }
            });
        }
        for (auto& t : pool) t.join();
        v->refresh();
        int nok = ok, nskip = skipped, nfail = failed;
        a.post([&a, nok, nskip, nfail, last_err] {
            a.tree_dirty = true;
            std::string m = "Uploaded " + std::to_string(nok) + " file(s)";
            if (nskip) m += ", skipped " + std::to_string(nskip);
            if (nfail) m += ", " + std::to_string(nfail) + " failed: " + last_err;
            a.notify(m, nfail > 0);
            if (a.engine) a.engine->request_sync();
        });
    });
}

// Downloads the whole vault into <dest>/<bucket>-<prefix>-<date>/. decrypt=true: plain files (needs the key).
// decrypt=false: objects exactly as stored (.gpg files + .s3vault/vault.json and key.gpg), so the copy stays
// protected by the password / recovery key and can be decrypted later with plain gpg.
void download_all(App& a, const std::string& dest_parent, bool decrypt) {
    auto v = a.vault;
    auto eng = a.engine;
    int workers = std::max(1, std::min(4, a.cfg.sync.concurrency));
    std::string pfx = a.cfg.storage.prefix;
    for (auto& ch : pfx) if (ch == '/') ch = '-';
    time_t t = time(nullptr);
    struct tm tmv {};
    localtime_r(&t, &tmv);
    char ts[32];
    strftime(ts, sizeof ts, "%Y%m%d-%H%M%S", &tmv);
    std::string dest = dest_parent + "/" + a.cfg.storage.bucket + "-" + pfx + "-" + ts + (decrypt ? "" : "-encrypted");
    a.run_job([&a, v, eng, dest, decrypt, workers] {
        std::vector<RemoteEntry> all;
        OpResult lr = v->refresh(&all);
        if (!lr.ok) { a.post([&a, e = lr.error] { a.notify(e, true); }); return; }
        struct Item { std::string key, out; uint64_t size; int tid; bool raw; };
        std::vector<Item> items;
        for (auto& e : all) {
            if (e.dir_marker) { mkdirs(dest + "/" + e.logical); continue; }
            if (decrypt) items.push_back({e.key, dest + "/" + e.logical, e.size, 0, false});
            else items.push_back({e.key, dest + "/" + e.key.substr(v->prefix().size()), e.size, 0, true});
        }
        if (!decrypt)  // vault metadata: needed to open the encrypted copy later
            for (const char* m : {".s3vault/vault.json", ".s3vault/key.gpg"})
                items.push_back({v->prefix() + m, dest + "/" + m, 0, 0, true});
        if (!mkdirs(dest, 0700)) { a.post([&a, dest] { a.notify("cannot create " + dest, true); }); return; }
        for (auto& it : items) it.tid = eng->transfer_begin("download", it.out.substr(dest.size() + 1), it.size, true);
        eng->log(std::string("download all (") + (decrypt ? "decrypted" : "encrypted, as stored") + "): " +
                 std::to_string(items.size()) + " file(s) → " + dest);
        std::atomic<size_t> next{0};
        std::atomic<int> ok{0}, failed{0};
        std::vector<std::thread> pool;
        for (int w = 0; w < workers; w++)
            pool.emplace_back([&] {
                for (size_t k; (k = next++) < items.size();) {
                    Item& it = items[k];
                    eng->transfer_start(it.tid);
                    OpResult r = it.raw ? v->download_raw(it.key, it.out) : v->download_to(it.key, it.out);
                    eng->transfer_end(it.tid);
                    if (r.ok) ok++;
                    else {
                        // key.gpg may not exist in a vault without password: not an error
                        if (!ends_with(it.key, ".s3vault/key.gpg")) { failed++; eng->log("download failed: " + it.key + " (" + r.error + ")"); }
                    }
                }
            });
        for (auto& th : pool) th.join();
        int nok = ok, nf = failed;
        eng->log("download all finished: " + std::to_string(nok) + " ok, " + std::to_string(nf) + " failed → " + dest);
        a.post([&a, nok, nf, dest] {
            a.notify("Downloaded " + std::to_string(nok) + " file(s) to " + display_path(dest) + (nf ? " — " + std::to_string(nf) + " failed (see Transfers)" : ""), nf > 0);
        });
    });
}

void start_download_all(App& a, bool decrypt) {
    if (decrypt && a.vault_has_key && !a.vault->unlocked()) {
        a.modal = "unlock";
        return;
    }
    a.modal.clear();
    browse(a, BrowseMode::Folder, decrypt ? "Download everything (decrypted) into…" : "Download everything (encrypted, as stored) into…",
           [&a, decrypt](std::vector<std::string> d) {
               download_all(a, d[0], decrypt);
               set_view(a, View::Transfers);  // show the queue
           });
}

void open_in_editor(App& a, const RemoteEntry& e) {
    if (e.encrypted && !a.vault->unlocked()) {
        a.modal = "unlock";
        return;
    }
    size_t cap = size_t(std::max(1, a.cfg.preview.text_max_mb)) << 20;
    if (e.size > cap + (e.encrypted ? 4096 : 0)) {
        a.notify("Too large for the built-in editor (" + human_size(e.size) + ", limit " + human_size(cap) + ")", true);
        return;
    }
    auto em = a.edits;
    a.run_job([&a, em, e] {
        std::string err;
        int id = em->open(e, err);
        a.post([&a, id, err, name = e.logical] {
            if (!id) {
                a.notify("Cannot edit " + name + ": " + err, true);
                return;
            }
            a.edit_focus = id;
            set_view(a, View::Editor);
        });
    });
}

void download_to_dialog(App& a, const RemoteEntry& e) {
    if (e.encrypted && !a.vault->unlocked()) {
        a.modal = "unlock";
        return;
    }
    auto v = a.vault;
    browse(a, BrowseMode::Save, "Download " + path_basename(e.logical), [&a, v, e](std::vector<std::string> paths) {
        std::string dest = paths[0];
        auto eng = a.engine;
        a.run_job([&a, v, eng, e, dest] {
            int tid = eng->transfer_begin("download", e.logical, e.size);
            OpResult r = v->download_to(e.key, dest);
            eng->transfer_end(tid);
            eng->log(r.ok ? "downloaded " + e.logical + " → " + dest : "download failed: " + e.logical + " (" + r.error + ")");
            a.post([&a, r, dest] { a.notify(r.ok ? "Saved " + dest : r.error, !r.ok); });
        });
    }, path_basename(e.logical));
}

}  // namespace s3v::ui
