// Sheets: every dialog is a centred card with an icon, a title, one line of explanation and a right-aligned
// button row (Cancel, then the blue primary action; destructive actions are red).
#include <GLFW/glfw3.h>

#include <algorithm>
#include <cstring>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "imgui.h"
#include "secret/strength.h"
#include "util/fs.h"
#include "util/secure.h"
#include "util/sha256.h"
#include "util/strings.h"

namespace s3v::ui {

static void wipe_buf(char* b, size_t n) { secure_zero(b, n); }

static std::string join_logical(const std::string& dir, const std::string& name) {
    return dir.empty() ? name : dir + "/" + name;
}

static std::string clean_path(std::string p) {
    p = trim(p);
    while (!p.empty() && p.front() == '/') p.erase(0, 1);
    while (!p.empty() && p.back() == '/') p.pop_back();
    return p;
}

static void close_sheet(App& a) {
    a.modal_error.clear();
    a.modal_busy = false;
    wipe_buf(a.pw1, sizeof a.pw1);
    wipe_buf(a.pw2, sizeof a.pw2);
    wipe_buf(a.pw_old, sizeof a.pw_old);
    sheet_close(a.modal);
}

static void sheet_status(App& a) {
    if (a.modal_busy) {
        spinner(7, P.dim);
        ImGui::SameLine();
        ImGui::TextDisabled("%s", tr("Working…"));
    }
    if (!a.modal_error.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, P.red);
        ImGui::TextWrapped("%s", a.modal_error.c_str());
        ImGui::PopStyleColor();
    }
}

static void run_sheet_job(App& a, std::function<OpResult()> fn, std::function<void()> on_ok = {}) {
    a.modal_busy = true;
    a.modal_error.clear();
    a.run_job([&a, fn, on_ok] {
        OpResult r = fn();
        a.post([&a, r, on_ok] {
            a.modal_busy = false;
            if (!r.ok) { a.modal_error = r.error; return; }
            a.modal.clear();
            if (on_ok) on_ok();
        });
    });
}

bool strength_meter(const char* pw, int min_len) {
    Strength s = check_password(pw, min_len);
    const char* labels[] = {"Very weak", "Weak", "Fair", "Strong", "Very strong"};
    ImVec4 c = s.score >= 3 ? P.green : s.score == 2 ? P.orange : P.red;
    float w = ImGui::GetContentRegionAvail().x;
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float seg = (w - 4 * 4) / 5;
    for (int i = 0; i < 5; i++) {
        ImVec2 a(p.x + float(i) * (seg + 4), p.y + 2), b(a.x + seg, a.y + 4);
        dl->AddRectFilled(a, b, col(pw[0] && i <= s.score ? c : P.track), 2);
    }
    ImGui::Dummy(ImVec2(w, 8));
    if (pw[0]) {
        ImGui::TextColored(c, "%s", labels[s.score]);
        for (auto& pr : s.problems) {
            ImGui::SameLine();
            small_dim("· %s", pr.c_str());
        }
    }
    return s.acceptable;
}

void password_pair(App& a, bool& acceptable) {
    sheet_field("Password", a.pw1, sizeof a.pw1, "At least 14 characters", true, true);
    sheet_field("Verify", a.pw2, sizeof a.pw2, "Type it again", true);
    acceptable = strength_meter(a.pw1, a.cfg.security.min_length);
    if (a.pw2[0] && strcmp(a.pw1, a.pw2) != 0) {
        ImGui::TextColored(P.red, "%s", tr("The passwords don't match."));
        acceptable = false;
    }
    if (!a.pw2[0]) acceptable = false;
    if (button(ICON_FA_WAND_MAGIC_SPARKLES "  Suggest a strong password", Btn::Plain)) {
        std::string g = generate_password();
        snprintf(a.pw1, sizeof a.pw1, "%s", g.c_str());
        snprintf(a.pw2, sizeof a.pw2, "%s", g.c_str());
        glfwSetClipboardString(a.win, g.c_str());
        a.notify(tr("Password copied — save it in your password manager"));
        wipe(g);
    }
}

static void list_box(const std::vector<std::string>& lines, size_t max_show = 6) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, P.track);
    float h = std::min<float>(float(std::min(lines.size(), max_show)), 6.0f) * ImGui::GetTextLineHeightWithSpacing() + 12;
    ImGui::BeginChild("##list", ImVec2(-1, h), ImGuiChildFlags_None, ImGuiWindowFlags_None);
    ImGui::SetCursorPos(ImVec2(10, 6));
    ImGui::BeginGroup();
    for (auto& l : lines) ImGui::TextUnformatted(l.c_str());
    ImGui::EndGroup();
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

void draw_modals(App& a) {
    auto v = a.vault;  // may be null before the first connection

    // ---- unlock (when an action needs the key) ----
    if (sheet_begin(a.modal, "unlock", 400)) {
        sheet_title(ICON_FA_LOCK, P.dim, "Enter Vault Password", "Encrypted files need the vault key. Sync keeps running after you unlock.");
        bool enter = sheet_field("Password", a.pw1, sizeof a.pw1, "", true, true);
        sheet_status(a);
        int r = sheet_buttons("Unlock", "Cancel", a.pw1[0] && !a.modal_busy && v);
        if ((r == 1 || (enter && a.pw1[0])) && !a.modal_busy && v) {
            std::string pw = a.pw1;
            wipe_buf(a.pw1, sizeof a.pw1);
            run_sheet_job(a, [v, pw]() mutable { OpResult x = v->unlock(pw); wipe(pw); return x; }, [&a] {
                a.tree_dirty = true;
                a.browse_locked = false;
                if (a.engine) a.engine->request_sync();
                if (!a.pending_uploads.empty()) a.modal = "upload";  // continue where the user was
            });
        } else if (r == 2) {
            a.pending_uploads.clear();
            close_sheet(a);
        }
        sheet_end();
    }

    // ---- set / change password ----
    for (const char* id : {"set-password", "change-password"}) {
        if (!sheet_begin(a.modal, id, 440)) continue;
        bool change = a.modal == "change-password";
        sheet_title(ICON_FA_KEY, P.accent, change ? "Change Vault Password" : "Set a Vault Password",
                    "Only the key file is re-encrypted. Your files and the recovery key stay as they are.");
        if (change) sheet_field("Current password", a.pw_old, sizeof a.pw_old, "", true, true);
        bool okpw = false;
        password_pair(a, okpw);
        sheet_status(a);
        int r = sheet_buttons(change ? "Change Password" : "Set Password", "Cancel", okpw && !a.modal_busy && (!change || a.pw_old[0]));
        if (r == 1 && v) {
            std::string old = a.pw_old, nw = a.pw1;
            run_sheet_job(a, [v, old, nw]() mutable { OpResult x = v->set_password(old, nw); wipe(old); wipe(nw); return x; },
                          [&a] { a.vault_has_key = true; a.notify(tr("Password saved")); });
        } else if (r == 2) {
            close_sheet(a);
        }
        sheet_end();
    }

    // ---- upload ----
    if (sheet_begin(a.modal, "upload", 500)) {
        size_t n = a.pending_uploads.size();
        std::string title = n == 1 ? trf("Upload \"%s\"", path_basename(a.pending_uploads[0]).c_str()) : trf("Upload %d Items", int(n));
        sheet_title(ICON_FA_CLOUD_ARROW_UP, P.accent, title.c_str(), "Folders are uploaded with everything inside them.");
        std::vector<std::string> lines;
        for (auto& f : a.pending_uploads) lines.push_back(display_path(f));
        if (n > 1) list_box(lines);
        sheet_field("To vault folder", a.text_buf, sizeof a.text_buf, "All Files (top level)");
        ImGui::Dummy(ImVec2(0, 2));
        int enc = a.upload_encrypt ? 1 : 0;
        small_dim("Encryption");
        if (!a.vault_has_key) {
            ImGui::TextDisabled("%s", tr("Set a vault password in Settings to upload encrypted files."));
        } else if (prefs::seg("enc", &enc, {"Plain", "Encrypted (OpenPGP)"})) {
            a.upload_encrypt = enc == 1;
        }
        small_dim("If a file with the same name exists");
        prefs::seg("exists", &a.upload_on_exists, {"Replace", "Keep both", "Skip"});
        bool need_key = a.upload_encrypt && v && !v->unlocked();
        if (need_key) ImGui::TextColored(P.orange, "%s", tr(ICON_FA_LOCK "  Unlock the vault to encrypt."));
        int r = sheet_buttons(need_key ? "Unlock…" : "Upload", "Cancel", true);
        if (r == 1) {
            if (need_key) {
                a.modal = "unlock";
            } else {
                upload_files(a, a.pending_uploads, clean_path(a.text_buf), a.upload_encrypt, a.upload_on_exists);
                a.pending_uploads.clear();
                close_sheet(a);
                set_view(a, View::Transfers);
            }
        } else if (r == 2) {
            a.pending_uploads.clear();
            close_sheet(a);
        }
        sheet_end();
    }

    // ---- new folder ----
    if (sheet_begin(a.modal, "new-folder", 420)) {
        if (ImGui::IsWindowAppearing()) snprintf(a.dir_buf, sizeof a.dir_buf, "%s", a.cwd.c_str());
        std::string where = a.dir_buf[0] ? std::string("In ") + a.dir_buf : "In All Files";
        sheet_title(ICON_FA_FOLDER_PLUS, P.folder, "New Folder", where.c_str());
        sheet_field("Name", a.text_buf, sizeof a.text_buf, "untitled folder", false, true);
        sheet_status(a);
        int r = sheet_buttons("Create", "Cancel", a.text_buf[0] && !a.modal_busy && v);
        if (r == 1) {
            std::string path = join_logical(clean_path(a.dir_buf), clean_path(a.text_buf));
            auto eng = a.engine;
            run_sheet_job(a, [v, eng, path] {
                OpResult x = v->mkdir(path);
                if (x.ok) { v->refresh(); eng->log("Created folder /" + path); }
                return x;
            }, [&a, path] { a.tree_dirty = true; a.selected = path; });
        } else if (r == 2) {
            close_sheet(a);
        }
        sheet_end();
    }

    // ---- rename / move ----
    if (sheet_begin(a.modal, "rename", 460)) {
        std::string sub = "Currently /" + a.modal_arg + ". Type a new name, or a path to move it.";
        sheet_title(ICON_FA_PEN, P.dim, "Rename", sub.c_str());
        sheet_field("New name or path", a.text_buf, sizeof a.text_buf, "", false, true);
        small_dim("Moving copies on the server; nothing is uploaded again.");
        sheet_status(a);
        std::string to = clean_path(a.text_buf);
        if (!to.empty() && to.find('/') == std::string::npos && a.modal_arg.find('/') != std::string::npos)
            to = path_dirname(a.modal_arg) + "/" + to;  // a bare name renames in place
        int r = sheet_buttons("Rename", "Cancel", !to.empty() && to != a.modal_arg && !a.modal_busy && v);
        if (r == 1) {
            std::string from = a.modal_arg;
            auto eng = a.engine;
            run_sheet_job(a, [v, eng, from, to] {
                OpResult x = v->rename(from, to);
                eng->log(x.ok ? "renamed /" + from + " → /" + to : "rename failed: /" + from + " (" + x.error + ")");
                return x;
            }, [&a, to] { a.selected = to; a.tree_dirty = true; if (a.engine) a.engine->request_sync(); });
        } else if (r == 2) {
            close_sheet(a);
        }
        sheet_end();
    }

    // ---- delete ----
    for (const char* id : {"delete", "delete-multi"}) {
        if (!sheet_begin(a.modal, id, 440)) continue;
        std::vector<std::string> targets;
        if (a.modal == "delete") targets.push_back(a.modal_arg);
        else targets.assign(a.multi.begin(), a.multi.end());
        std::string title = targets.size() == 1 ? trf("Move \"%s\" to the Trash?", path_basename(targets[0]).c_str())
                                                : trf("Move %d Items to the Trash?", int(targets.size()));
        std::string sub = trf("You can restore it from Trash for %d days. Synced copies on your other devices move to their trash too.",
                              a.cfg.sync.trash_days);
        sheet_title(ICON_FA_TRASH, P.red, title.c_str(), sub.c_str());
        if (targets.size() > 1) {
            std::vector<std::string> lines;
            for (auto& t : targets) lines.push_back("/" + t);
            list_box(lines);
        }
        sheet_status(a);
        int r = sheet_buttons("Move to Trash", "Cancel", !a.modal_busy && v, true);
        if (r == 1) {
            auto eng = a.engine;
            run_sheet_job(a, [v, eng, targets] {
                for (auto& t : targets) {
                    OpResult x = v->remove(t);
                    eng->log(x.ok ? "deleted /" + t + " (to vault trash)" : "delete failed: /" + t + " (" + x.error + ")");
                    if (!x.ok) return x;
                }
                return OpResult::success();
            }, [&a] {
                a.multi.clear();
                preview_free(a);
                a.selected.clear();
                a.tree_dirty = true;
                a.trash_dirty = true;
                if (a.engine) a.engine->request_sync();
            });
        } else if (r == 2) {
            close_sheet(a);
        }
        sheet_end();
    }

    // ---- keep a folder in sync ----
    if (sheet_begin(a.modal, "add-root", 520)) {
        std::string sub = trf("%s will stay in sync with a folder in your vault.", display_path(a.modal_arg).c_str());
        sheet_title(ICON_FA_ARROWS_ROTATE, P.green, "Keep a Folder in Sync", sub.c_str());
        sheet_field("Vault folder", a.text_buf, sizeof a.text_buf, "e.g. Documents");
        small_dim("Direction");
        prefs::seg("dir", &a.upload_on_exists, {"Both ways", "Back up only", "Mirror only"});
        const char* dir_help[] = {"Changes on either side are copied to the other.",
                                  "Local changes go up; nothing is downloaded or deleted here.",
                                  "The folder becomes a copy of the vault; local changes are not uploaded."};
        small_dim("%s", dir_help[std::clamp(a.upload_on_exists, 0, 2)]);
        if (a.vault_has_key) {
            int enc = a.upload_encrypt ? 1 : 0;
            small_dim("New files");
            if (prefs::seg("enc", &enc, {"Plain", "Encrypted"})) a.upload_encrypt = enc == 1;
        }
        sheet_status(a);
        int r = sheet_buttons("Start Syncing", "Cancel", a.text_buf[0] && a.engine);
        if (r == 1) {
            const char* dirs[] = {"two-way", "upload-only", "download-only"};
            std::string err;
            int id = a.engine->add_root(a.modal_arg, clean_path(a.text_buf), dirs[std::clamp(a.upload_on_exists, 0, 2)],
                                        a.upload_encrypt && a.vault_has_key, err);
            if (!id) {
                a.modal_error = err;
            } else {
                std::string rp = clean_path(a.text_buf);
                close_sheet(a);
                a.engine->request_sync();
                a.tree_dirty = true;
                a.notify(trf("Syncing %s", display_path(a.modal_arg).c_str()));
                navigate(a, rp);
            }
        } else if (r == 2) {
            close_sheet(a);
        }
        sheet_end();
    }

    if (sheet_begin(a.modal, "remove-root", 420)) {
        sheet_title(ICON_FA_LINK_SLASH, P.dim, "Stop Syncing This Folder?", "Nothing is deleted: the local files and the vault copies stay where they are.");
        int r = sheet_buttons("Stop Syncing", "Cancel", true, true);
        if (r == 1) {
            a.db.remove_root(atoi(a.modal_arg.c_str()));
            a.tree_dirty = true;
            close_sheet(a);
        } else if (r == 2) {
            close_sheet(a);
        }
        sheet_end();
    }

    // ---- resolve conflicts ----
    if (sheet_begin(a.modal, "resolve", 500)) {
        std::string how = a.modal_arg;
        const char* title = how == "keep-both" ? "Keep Both Versions?" : how == "keep-local" ? "Use This Device's Version?"
                          : how == "keep-remote" ? "Use the Server's Version?" : "Use the Newest Version?";
        const char* sub = how == "keep-both" ? "The server's copy is saved next to yours as \"name (conflict remote …)\"."
                        : how == "keep-local" ? "Your version replaces the one on the server."
                        : how == "keep-remote" ? "The server's version replaces yours; your file goes to the desktop trash."
                                               : "Whichever side was changed last is kept.";
        sheet_title(ICON_FA_CODE_MERGE, P.orange, title, sub);
        std::vector<std::string> lines;
        for (auto& c : a.db.conflicts())
            if (a.conflict_sel.count(c.id)) lines.push_back(c.rel);
        list_box(lines);
        sheet_status(a);
        int r = sheet_buttons("Apply", "Cancel", !a.modal_busy && v && !lines.empty());
        if (r == 1) {
            std::vector<int64_t> ids(a.conflict_sel.begin(), a.conflict_sel.end());
            Resolution res = how == "keep-both" ? Resolution::KeepBoth : how == "keep-local" ? Resolution::KeepLocal
                           : how == "keep-remote" ? Resolution::KeepRemote : Resolution::KeepNewest;
            auto e = a.engine;
            if (!v->unlocked() && a.vault_has_key) {
                a.modal = "unlock";
            } else {
                run_sheet_job(a, [e, v, ids, res] {
                    int fails = 0;
                    std::string last;
                    for (auto id : ids) {
                        OpResult x = e->resolve(id, res);
                        if (!x.ok) { fails++; last = x.error; }
                    }
                    v->refresh();
                    if (fails) return OpResult::fail(std::to_string(fails) + " could not be resolved: " + last);
                    return OpResult::success();
                }, [&a, n = ids.size()] { a.conflict_sel.clear(); a.tree_dirty = true; a.notify(trf("Resolved %s", tr_n(n, "%zu conflict", "%zu conflicts").c_str())); });
            }
        } else if (r == 2) {
            close_sheet(a);
        }
        sheet_end();
    }

    // ---- compare ----
    if (sheet_begin(a.modal, "compare", 920)) {
        static int64_t loaded_id = 0;
        static std::string local_txt, remote_txt, err;
        static bool loading = false;
        int64_t id = atoll(a.modal_arg.c_str());
        ConflictRow c{};
        bool have = a.db.conflict(id, c);
        if (have && loaded_id != id && !loading && v) {
            loading = true;
            loaded_id = id;
            wipe(local_txt);
            wipe(remote_txt);
            err.clear();
            std::string root_path;
            for (auto& rr : a.db.roots())
                if (rr.id == c.root_id) root_path = rr.local_path;
            size_t cap = size_t(a.cfg.preview.text_max_mb) << 20;
            a.run_job([&a, v, c, root_path, cap] {
                std::string l, r, e;
                if (c.local_exists && !read_file(root_path + "/" + c.rel, l, cap)) e = "The local file is too large or unreadable.";
                if (c.remote_exists) {
                    OpResult o = v->download_to_memory(c.remote_key, r, cap);
                    if (!o.ok) e = o.error;
                }
                a.post([l, r, e]() mutable { local_txt = std::move(l); remote_txt = std::move(r); err = e; loading = false; });
            });
        }
        sheet_title(nullptr, P.dim, have ? path_basename(c.rel).c_str() : "Resolved", have ? ("/" + c.rel).c_str() : nullptr);
        if (loading) { spinner(7, P.dim); ImGui::SameLine(); ImGui::TextDisabled("%s", tr("Loading…")); }
        if (!err.empty()) ImGui::TextColored(P.red, "%s", err.c_str());
        bool text = preview_kind(c.rel) == PreviewKind::Text && utf8_valid(local_txt) && utf8_valid(remote_txt);
        float colw = (ImGui::GetContentRegionAvail().x - 12) / 2;
        for (int side = 0; side < 2; side++) {
            if (side) ImGui::SameLine(0, 12);
            ImGui::BeginGroup();
            const char* hdr = side == 0 ? "This device" : "Server";
            const std::string& t = side == 0 ? local_txt : remote_txt;
            bool exists = side == 0 ? c.local_exists : c.remote_exists;
            std::string meta = exists ? human_size(side == 0 ? c.local_size : c.remote_size) + " · " +
                                            format_local_time(side == 0 ? c.local_mtime : c.remote_mtime)
                                      : "deleted";
            ImGui::Text("%s", hdr);
            ImGui::SameLine();
            small_dim("%s", meta.c_str());
            ImGui::PushStyleColor(ImGuiCol_ChildBg, P.track);
            ImGui::BeginChild(side == 0 ? "##l" : "##r", ImVec2(colw, 400), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
            ImGui::SetCursorPos(ImVec2(10, 8));
            ImGui::BeginGroup();
            if (!exists) ImGui::TextDisabled("%s", tr("(deleted)"));
            else if (text) {
                if (g_mono) ImGui::PushFont(g_mono, 0.0f);
                ImGui::TextUnformatted(t.data(), t.data() + t.size());
                if (g_mono) ImGui::PopFont();
            } else ImGui::TextDisabled(tr("%s · SHA-256 %s"), human_size(t.size()).c_str(), sha256_hex(t).substr(0, 16).c_str());
            ImGui::EndGroup();
            ImGui::EndChild();
            ImGui::PopStyleColor();
            ImGui::EndGroup();
        }
        int r = sheet_buttons(nullptr, "Done");
        if (r == 2) {
            wipe(local_txt);
            wipe(remote_txt);
            loaded_id = 0;
            close_sheet(a);
        }
        sheet_end();
    }

    // ---- export key ----
    if (sheet_begin(a.modal, "export-key", 520)) {
        sheet_title(ICON_FA_KEY, P.accent, "Export Key", nullptr);
        ImGui::Text("%s", tr("Backup key file"));
        ImGui::PushStyleColor(ImGuiCol_Text, P.dim);
        ImGui::TextWrapped("%s", tr("A copy of key.gpg, still protected by your password. Safe to keep anywhere. "
                           "With it and your password the vault opens even if the server's copy is lost."));
        ImGui::PopStyleColor();
        ImGui::BeginDisabled(a.modal_busy);
        if (button(ICON_FA_DOWNLOAD "  Save Key File…")) {
            close_sheet(a);  // the file browser takes over
            browse(a, BrowseMode::Save, "Save Key File", [&a, v](std::vector<std::string> p) {
                std::string dest = p[0];
                a.run_job([&a, v, dest] {
                    std::string ct;
                    OpResult x = v->key_file(ct);
                    if (x.ok && !write_file_atomic(dest, ct, 0600)) x = OpResult::fail("cannot write " + dest);
                    a.post([&a, x, dest] { a.notify(x.ok ? trf("Saved key file to %s", display_path(dest).c_str()) : x.error, !x.ok); });
                });
            }, "s3vault-" + a.cfg.storage.bucket + "-key.gpg");
        }
        ImGui::EndDisabled();
        ImGui::Dummy(ImVec2(0, 6));
        ImGui::Separator();
        ImGui::Dummy(ImVec2(0, 4));
        ImGui::TextColored(P.orange, "%s", tr(ICON_FA_TRIANGLE_EXCLAMATION "  Recovery key"));
        ImGui::PushStyleColor(ImGuiCol_Text, P.dim);
        ImGui::TextWrapped("%s", tr("The raw vault key. Anyone who has it can read every file without your password, and changing the "
                           "password does not change it. Keep it offline — in a password manager or on paper."));
        ImGui::PopStyleColor();
        sheet_field("Confirm with your vault password", a.pw1, sizeof a.pw1, "", true);
        sheet_status(a);
        auto get_key = [&](std::function<void(std::string)> use) {
            std::string pw = a.pw1;
            wipe_buf(a.pw1, sizeof a.pw1);
            a.modal_busy = true;
            a.run_job([&a, v, pw, use]() mutable {
                SecureString k;
                OpResult x = v->recovery_key(pw, k);
                wipe(pw);
                std::string key(k.view());
                a.post([&a, x, key, use]() mutable {
                    a.modal_busy = false;
                    if (!x.ok) a.modal_error = x.error;
                    else { a.modal_error.clear(); use(key); }
                    wipe(key);
                });
            });
        };
        bool can = a.pw1[0] && !a.modal_busy && v;
        if (button("Copy Recovery Key", Btn::Secondary, ImVec2(0, 0), can)) {
            get_key([&a](std::string k) {
                glfwSetClipboardString(a.win, k.c_str());
                a.notify(tr("Recovery key copied — paste it into your password manager"));
            });
        }
        ImGui::SameLine();
        if (button("Save Recovery Key…", Btn::Secondary, ImVec2(0, 0), can)) {
            get_key([&a](std::string k) {
                auto keep = std::make_shared<SecureString>(k);
                a.modal.clear();
                browse(a, BrowseMode::Save, "Save Recovery Key", [&a, keep](std::vector<std::string> p) {
                    std::string text = "s3vault recovery key (vault " + a.cfg.storage.bucket + "/" + a.cfg.storage.prefix + ")\n"
                                       "Decrypt any file:  gpg -d <file>.gpg   and use this as the passphrase:\n" +
                                       std::string(keep->view()) + "\n";
                    bool ok = write_file_atomic(p[0], text, 0600);
                    wipe(text);
                    a.notify(ok ? trf("Saved recovery key to %s (only you can read it)", display_path(p[0]).c_str()) : trf("Can't write %s", p[0].c_str()), !ok);
                }, "s3vault-recovery-key.txt");
            });
        }
        if (sheet_buttons(nullptr, "Done") == 2) close_sheet(a);
        sheet_end();
    }

    // ---- empty trash ----
    if (sheet_begin(a.modal, "empty-trash", 420)) {
        sheet_title(ICON_FA_TRASH, P.red, "Empty the Vault Trash?", "Everything in the trash is deleted from the server for good. This can't be undone.");
        sheet_status(a);
        int r = sheet_buttons("Empty Trash", "Cancel", !a.modal_busy && v, true);
        if (r == 1) {
            auto eng = a.engine;
            run_sheet_job(a, [v, eng] {
                int n = 0;
                OpResult x = v->purge_trash(0, &n);
                eng->log("Emptied the vault trash: " + plural(n, "object") + " deleted");
                return x;
            }, [&a] { a.trash_dirty = true; a.trash_sel.clear(); a.notify(tr("Trash emptied")); });
        } else if (r == 2) {
            close_sheet(a);
        }
        sheet_end();
    }

    // ---- quit with unsaved edits ----
    if (sheet_begin(a.modal, "quit-unsaved", 440)) {
        sheet_title(ICON_FA_PEN_TO_SQUARE, P.orange, "Save Your Changes Before Quitting?", "Some files in the editor have unsaved changes.");
        sheet_status(a);
        auto em = a.edits;
        int extra = 0;
        int r = sheet_buttons("Save All", "Cancel", !a.modal_busy && em, false, "Don't Save", &extra);
        if (extra && em) {
            em->close_all();
            close_sheet(a);
            a.quit_confirmed = true;
        } else if (r == 1) {
            std::vector<std::pair<int, std::string>> todo;
            for (int id : em->ids())
                if (EditDoc* d = em->doc(id); d && d->dirty()) todo.push_back({id, d->text});
            run_sheet_job(a, [em, todo] {
                for (auto& [id, text] : todo) {
                    OpResult x = em->save(id, text);
                    if (!x.ok) return OpResult::fail(em->doc(id) ? em->doc(id)->logical + ": " + x.error : x.error);
                    em->apply_saved(id, text, x.etag);
                }
                return OpResult::success();
            }, [&a] { a.quit_confirmed = true; });
        } else if (r == 2) {
            a.quit_requested = false;
            close_sheet(a);
        }
        sheet_end();
    }
}

}  // namespace s3v::ui
