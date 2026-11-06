// "Replace Vault Key" wizard. Replacing the key re-encrypts every encrypted object, so the sheet asks three
// times before anything changes on the server:
//   1. Impact: what happens, how much, when to use it (and when "Change Password" is enough) → a checkbox.
//   2. The new recovery key: shown before anything changes; must be copied or saved, then typed back (last 8).
//   3. Final: type ROTATE; the red button names the number of files.
// Then progress (Pause is safe), and a result page with what to do next. An unfinished run is resumed with
// the new password alone (Settings › Finish key replacement, or the lock screen).
#include <GLFW/glfw3.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <ctime>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "imgui.h"
#include "secret/strength.h"
#include "util/fs.h"
#include "util/secure.h"
#include "util/strings.h"

namespace s3v::ui {

static void wipe_buf(char* b, size_t n) { secure_zero(b, n); }

// Text that wraps, after a bullet.
static void bullet(const char* text, const ImVec4* color = nullptr) {
    ImGui::Bullet();
    ImGui::SameLine();
    ImGui::PushTextWrapPos(0);
    if (color) ImGui::PushStyleColor(ImGuiCol_Text, *color);
    ImGui::TextUnformatted(tr(text));
    if (color) ImGui::PopStyleColor();
    ImGui::PopTextWrapPos();
}

static void para(const char* text, const ImVec4& c) {
    ImGui::PushStyleColor(ImGuiCol_Text, c);
    ImGui::TextWrapped("%s", tr(text));
    ImGui::PopStyleColor();
}

static void step_label(int n) {
    small_dim("%s", trf("Confirmation %d of 3", n).c_str());
}

static void reset(App& a) {
    App::Rotation& r = a.rot;
    r.step = 0;
    r.ack = false;
    r.stats_loading = r.stats_ok = false;
    r.stats = RotationStats{};
    r.stats_error.clear();
    r.key.clear();
    r.old_pw.clear();
    r.new_pw.clear();
    r.key_saved = false;
    wipe_buf(r.confirm, sizeof r.confirm);
    wipe_buf(r.go, sizeof r.go);
    r.resume = false;
    r.cancel = false;
    r.result = OpResult{};
    wipe_buf(a.pw1, sizeof a.pw1);
    wipe_buf(a.pw2, sizeof a.pw2);
    wipe_buf(a.pw_old, sizeof a.pw_old);
    a.modal_error.clear();
    a.modal_busy = false;
}

static void close_wizard(App& a) {
    reset(a);
    sheet_close(a.modal);
}

static void load_stats(App& a) {
    auto v = a.vault;
    if (!v) return;
    a.rot.stats_loading = true;
    a.run_job([&a, v] {
        RotationStats st;
        OpResult r = v->rotation_stats(st);
        a.post([&a, r, st] {
            a.rot.stats_loading = false;
            a.rot.stats_ok = r.ok;
            a.rot.stats = st;
            a.rot.stats_error = r.ok ? "" : r.error;
        });
    });
}

void check_rotation_state(App& a) {
    auto v = a.vault;
    if (!v || !v->connected()) return;
    a.run_job([&a, v] {
        RotationStatus rs;
        OpResult r = v->rotation_status(rs);
        if (!r.ok) return;
        a.post([&a, v, rs] {
            if (a.vault != v) return;
            a.rot.server_active = rs.active;
            a.rot.server_device = rs.device;
            a.rot.server_started = rs.started;
        });
    });
}

void handle_key_notice(App& a) {
    if (!a.vault) return;
    std::string n = a.vault->take_key_notice();
    if (n.empty()) return;
    a.notify(tr(n.c_str()), true);
    a.tree_dirty = true;
    preview_free(a);
    check_rotation_state(a);
}

void open_rotation(App& a) {
    if (a.rot.server_active && a.rot.step != 4 && a.rot.step != 5) { open_rotation_resume(a); return; }
    // Coming back from the file browser (saving the new recovery key) keeps the wizard where it was.
    bool keep = (a.rot.step >= 1 && a.rot.step <= 5) || (a.rot.step == 0 && a.rot.ack);
    if (!keep) {
        reset(a);
        load_stats(a);
    }
    a.modal = "rotate-key";
}

void open_rotation_resume(App& a) {
    if (a.rot.step == 4) { a.modal = "rotate-key"; return; }
    reset(a);
    a.rot.resume = true;
    a.rot.step = 10;
    a.modal = "rotate-key";
}

static std::string grouped_key(std::string_view k) {
    std::string out;
    for (size_t i = 0; i < k.size(); i += 4) {
        if (i) out += (i % 16 == 0) ? "\n" : "  ";
        out += std::string(k.substr(i, 4));
    }
    return out;
}

static std::string normalized_tail(const char* typed) {
    std::string s;
    for (const char* p = typed; *p; p++)
        if (isxdigit(static_cast<unsigned char>(*p))) s += char(tolower(static_cast<unsigned char>(*p)));
    return s;
}

static int total_files(const App& a) { return a.rot.stats.files + a.rot.stats.trash_files; }

static void start_run(App& a) {
    App::Rotation& r = a.rot;
    if (a.edits && !a.edits->ids().empty()) {
        a.modal_error = tr("Close the files open in the editor first, so no unsaved change is written with the old key.");
        return;
    }
    r.step = 4;
    r.cancel = false;
    {
        std::lock_guard<std::mutex> lk(r.mu);
        r.progress = RotationProgress{};
    }
    a.modal_error.clear();
    auto v = a.vault;
    auto eng = a.engine;
    std::string old_pw(r.old_pw.view()), new_pw(r.new_pw.view()), key(r.key.view());
    bool resume = r.resume;
    r.old_pw.clear();
    r.new_pw.clear();
    r.key.clear();
    if (eng) eng->log(resume ? "Resuming the vault key replacement" : "Replacing the vault key: re-encrypting every encrypted file");
    a.run_job([&a, v, eng, old_pw, new_pw, key, resume]() mutable {
        if (eng) eng->stop();  // no sync pass may write with the old key meanwhile
        auto progress = [&a](const RotationProgress& p) {
            std::lock_guard<std::mutex> lk(a.rot.mu);
            a.rot.progress = p;
        };
        OpResult res = resume ? v->resume_rotation(new_pw, progress, &a.rot.cancel)
                              : v->rotate_key(old_pw, new_pw, key, progress, &a.rot.cancel);
        wipe(old_pw);
        wipe(new_pw);
        wipe(key);
        if (eng) {
            RotationProgress p;
            {
                std::lock_guard<std::mutex> lk(a.rot.mu);
                p = a.rot.progress;
            }
            eng->log(res.ok ? "Vault key replaced: " + plural(size_t(p.done), "file") + " re-encrypted"
                            : "Vault key replacement " + std::string(res.paused ? "paused" : "stopped") + ": " + res.error);
        }
        a.post([&a, v, eng, res] {
            a.rot.result = res;
            a.rot.step = 5;
            a.rot.server_active = !res.ok && res.rotating;
            if (res.ok) {
                a.vault_has_key = true;
                a.browse_locked = false;
                a.rot.server_device.clear();
            }
            a.tree_dirty = true;
            a.trash_dirty = true;
            preview_free(a);
            if (eng && a.vault == v) {
                eng->start();
                eng->request_sync();
            }
        });
    });
}

// ---------------------------------------------------------------------------------------------------

static void draw_impact(App& a) {
    App::Rotation& r = a.rot;
    sheet_title(ICON_FA_ARROWS_ROTATE, P.red, "Replace the Vault Key?",
                "Every encrypted file is re-encrypted with a new key. Use it only if the key may have leaked.");
    step_label(1);
    ImGui::Text("%s", tr("Use this when"));
    bullet("your password leaked AND an old copy of key.gpg may exist (bucket versions, backups, exports), or");
    bullet("your recovery key leaked, or a computer that had the vault unlocked was lost.");
    ImGui::Dummy(ImVec2(0, 2));
    para("Only want a new password? Use Change Password instead: it's instant and re-encrypts nothing.", P.dim);
    if (button(ICON_FA_KEY "  Change Password Instead", Btn::Plain)) {
        close_wizard(a);
        a.modal = "change-password";
        return;
    }
    ImGui::Dummy(ImVec2(0, 4));
    ImGui::Separator();
    ImGui::Dummy(ImVec2(0, 4));
    ImGui::Text("%s", tr("What happens"));
    if (r.stats_loading) {
        spinner(7, P.dim);
        ImGui::SameLine();
        ImGui::TextDisabled("%s", tr("Counting encrypted files…"));
    } else if (!r.stats_ok) {
        ImGui::TextColored(P.red, "%s", r.stats_error.c_str());
    } else {
        std::string line = trf("%s (%d in the vault trash), %s, are downloaded, decrypted and uploaded again.",
                               tr_n(size_t(total_files(a)), "%zu encrypted file", "%zu encrypted files").c_str(),
                               r.stats.trash_files, human_size(r.stats.bytes).c_str());
        bullet(line.c_str());
        if (r.stats.plain_files)
            bullet(trf("%s: not encrypted, not touched.", tr_n(size_t(r.stats.plain_files), "%zu plain file", "%zu plain files").c_str()).c_str());
    }
    bullet("You choose a new password and get a new recovery key. The old password, old recovery key and old copies of "
           "key.gpg stop opening the re-encrypted files.");
    bullet("Sync pauses on this computer while it runs. Other devices stop syncing encrypted files at once and must "
           "unlock with the new password.");
    bullet("If it's interrupted, nothing is lost: finish it later with the new password.");
    const ImVec4 warn = P.orange;
    bullet("It can't be undone. Copies made earlier (bucket versions, backups, \"as stored\" downloads) are not changed.", &warn);
    ImGui::Dummy(ImVec2(0, 4));
    ImGui::Checkbox("##ack", &r.ack);
    ImGui::SameLine();
    ImGui::PushTextWrapPos(0);
    ImGui::TextUnformatted(tr("I understand: every encrypted file is re-encrypted, other devices must unlock again with the "
                              "new password, and this can't be undone."));
    ImGui::PopTextWrapPos();
    int b = sheet_buttons("Continue", "Cancel", r.ack && r.stats_ok && !r.stats_loading);
    if (b == 1) r.step = 1;
    else if (b == 2) close_wizard(a);
}

static void draw_passwords(App& a) {
    App::Rotation& r = a.rot;
    sheet_title(ICON_FA_KEY, P.accent, "Choose a New Password", "Your current password confirms it's you. The new one protects the new key.");
    sheet_field("Current password", a.pw_old, sizeof a.pw_old, "", true, true);
    ImGui::Dummy(ImVec2(0, 2));
    bool ok = false;
    password_pair(a, ok);
    bool same = a.pw_old[0] && strcmp(a.pw_old, a.pw1) == 0;
    if (same) {
        ImGui::TextColored(P.red, "%s", tr("The new password must be different from the current one."));
        ok = false;
    }
    small_dim("%s", tr("Save the new password in your password manager now. Other devices need it to unlock."));
    if (a.modal_busy) {
        spinner(7, P.dim);
        ImGui::SameLine();
        ImGui::TextDisabled("%s", tr("Checking…"));
    }
    if (!a.modal_error.empty()) ImGui::TextColored(P.red, "%s", a.modal_error.c_str());
    int b = sheet_buttons("Continue", "Back", ok && a.pw_old[0] && !a.modal_busy);
    if (b == 1) {
        auto v = a.vault;
        std::string old = a.pw_old, nw = a.pw1;
        a.modal_busy = true;
        a.modal_error.clear();
        a.run_job([&a, v, old, nw]() mutable {
            OpResult x = v->verify_password(old);  // nothing changes on the server yet
            a.post([&a, x, old, nw]() mutable {
                a.modal_busy = false;
                if (!x.ok) {
                    a.modal_error = x.bad_key ? tr("Wrong current password.") : x.error;
                } else {
                    a.rot.old_pw.assign(old);
                    a.rot.new_pw.assign(nw);
                    a.rot.key.assign(Vault::new_vault_key());
                    a.rot.key_saved = false;
                    wipe_buf(a.pw_old, sizeof a.pw_old);
                    wipe_buf(a.pw1, sizeof a.pw1);
                    wipe_buf(a.pw2, sizeof a.pw2);
                    a.rot.step = 2;
                }
                wipe(old);
                wipe(nw);
            });
        });
    } else if (b == 2) {
        a.modal_error.clear();
        r.step = 0;
    }
}

static void draw_new_key(App& a) {
    App::Rotation& r = a.rot;
    sheet_title(ICON_FA_TRIANGLE_EXCLAMATION, P.orange, "Save the New Recovery Key",
                "It replaces every earlier recovery key. Keep it offline, in a password manager or on paper.");
    step_label(2);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, P.track);
    ImGui::BeginChild("##newkey", ImVec2(-1, 0), ImGuiChildFlags_AutoResizeY, ImGuiWindowFlags_NoScrollbar);
    ImGui::SetCursorPos(ImVec2(14, 9));
    if (g_mono) ImGui::PushFont(g_mono);
    std::string shown = grouped_key(r.key.view());
    ImGui::TextUnformatted(shown.c_str());
    wipe(shown);
    if (g_mono) ImGui::PopFont();
    ImGui::Dummy(ImVec2(0, 4));
    ImGui::EndChild();
    ImGui::PopStyleColor();
    if (button(ICON_FA_COPY "  Copy", Btn::Secondary)) {
        glfwSetClipboardString(a.win, std::string(r.key.view()).c_str());
        r.key_saved = true;
        a.notify(tr("New recovery key copied — paste it into your password manager, then clear the clipboard"));
    }
    ImGui::SameLine();
    if (button(ICON_FA_DOWNLOAD "  Save to a File…", Btn::Secondary)) {
        auto keep = std::make_shared<SecureString>(r.key.view());
        std::string where = a.cfg.storage.bucket + "/" + a.cfg.storage.prefix;
        a.modal.clear();  // the file browser takes over; Settings › Replace vault key comes back here
        browse(a, BrowseMode::Save, "Save New Recovery Key", [&a, keep, where](std::vector<std::string> p) {
            std::string text = "s3vault NEW recovery key (vault " + where + "), made " + format_local_time(time(nullptr)) +
                               " by a key replacement.\nIt replaces every earlier recovery key of this vault.\n"
                               "Decrypt any file:  gpg -d <file>.gpg   and use this as the passphrase:\n" +
                               std::string(keep->view()) + "\n";
            bool ok = write_file_atomic(p[0], text, 0600);
            wipe(text);
            if (ok) a.rot.key_saved = true;
            a.notify(ok ? trf("Saved the new recovery key to %s (only you can read it)", display_path(p[0]).c_str())
                        : trf("Can't write %s", p[0].c_str()), !ok);
            a.modal = "rotate-key";
        }, "s3vault-NEW-recovery-key.txt");
        return;
    }
    if (r.key_saved) {
        ImGui::SameLine();
        ImGui::TextColored(P.green, "%s", tr(ICON_FA_CIRCLE_CHECK "  Saved"));
    }
    ImGui::Dummy(ImVec2(0, 4));
    std::string tail(r.key.view().substr(r.key.size() >= 8 ? r.key.size() - 8 : 0));
    sheet_field("Type the last 8 characters of the new key", r.confirm, sizeof r.confirm, "e.g. 1a2b 3c4d");
    bool typed = normalized_tail(r.confirm) == tail;
    wipe(tail);
    if (r.confirm[0] && !typed && strlen(r.confirm) >= 8) ImGui::TextColored(P.red, "%s", tr("That doesn't match the end of the new key."));
    if (!r.key_saved) small_dim("%s", tr("Copy or save the key first."));
    int b = sheet_buttons("Continue", "Back", typed && r.key_saved);
    if (b == 1) r.step = 3;
    else if (b == 2) {
        // Back to the passwords: this key was never used; a new one is made on Continue.
        r.key.clear();
        r.old_pw.clear();
        r.new_pw.clear();
        wipe_buf(r.confirm, sizeof r.confirm);
        r.step = 1;
    }
}

static void draw_final(App& a) {
    App::Rotation& r = a.rot;
    sheet_title(ICON_FA_ARROWS_ROTATE, P.red, "Re-encrypt Every Encrypted File?", "Last check. After this, only the new password and the new recovery key open the vault.");
    step_label(3);
    bullet(trf("%d files, %s, are re-encrypted. Keep this computer awake and online.", total_files(a),
               human_size(a.rot.stats.bytes).c_str()).c_str());
    bullet("Other devices stop syncing encrypted files now, and unlock again with the new password.");
    bullet("Make sure the new password and the new recovery key are saved where you can find them.");
    ImGui::Dummy(ImVec2(0, 4));
    sheet_field("Type ROTATE to confirm", r.go, sizeof r.go, "ROTATE", false, true);
    if (!a.modal_error.empty()) ImGui::TextColored(P.red, "%s", a.modal_error.c_str());
    bool go = strcmp(r.go, "ROTATE") == 0;
    std::string label = trf("Re-encrypt %d Files", total_files(a));
    int b = sheet_buttons(label.c_str(), "Back", go, /*destructive=*/true);
    if (b == 1) start_run(a);
    else if (b == 2) {
        wipe_buf(r.go, sizeof r.go);
        a.modal_error.clear();
        r.step = 2;
    }
}

static void draw_running(App& a) {
    App::Rotation& r = a.rot;
    RotationProgress p;
    {
        std::lock_guard<std::mutex> lk(r.mu);
        p = r.progress;
    }
    sheet_title(ICON_FA_ARROWS_ROTATE, P.accent, r.cancel ? "Pausing…" : "Replacing the Vault Key…",
                "Keep s3vault open. Pausing is safe; finish later with the new password.");
    float frac = p.finishing ? 1.0f : p.bytes_total ? float(double(p.bytes_done) / double(p.bytes_total)) : 0.0f;
    ImGui::ProgressBar(frac, ImVec2(-1, 0));
    if (p.finishing) ImGui::TextDisabled("%s", tr("Making the new key the vault key…"));
    else {
        ImGui::TextDisabled("%s", trf("%d of %d files · %s of %s", p.done, p.total, human_size(p.bytes_done).c_str(),
                                      human_size(p.bytes_total).c_str()).c_str());
        if (!p.current.empty()) {
            ImGui::PushTextWrapPos(0);
            ImGui::TextDisabled("%s", p.current.c_str());
            ImGui::PopTextWrapPos();
        }
        if (p.pass > 1) small_dim("%s", tr("Some files changed meanwhile; re-encrypting them too."));
    }
    if (r.cancel) {  // sheet_buttons() needs at least one button
        ImGui::Dummy(ImVec2(0, 6));
        spinner(7, P.dim);
        ImGui::SameLine();
        ImGui::TextDisabled("%s", tr("Stopping after the current file…"));
    } else if (sheet_buttons(nullptr, "Pause", true) == 2) {
        r.cancel = true;
    }
}

static void draw_finished(App& a) {
    App::Rotation& r = a.rot;
    RotationProgress p;
    {
        std::lock_guard<std::mutex> lk(r.mu);
        p = r.progress;
    }
    if (r.result.ok) {
        sheet_title(ICON_FA_CIRCLE_CHECK, P.green, "The Vault Key Was Replaced",
                    trf("%d files are now encrypted with the new key.", p.done - p.already_new - p.unreadable).c_str());
        if (p.unreadable)
            ImGui::TextColored(P.orange, "%s", trf("%d files couldn't be opened with the old or the new key and were left as they were.", p.unreadable).c_str());
        ImGui::Text("%s", tr("Next steps"));
        bullet("Other devices: unlock with the new password.");
        bullet("Delete what still holds the old key: exported key files, the old recovery key, and \"as stored\" downloads.");
        bullet("If your bucket keeps old versions (versioning), delete the old versions in your storage provider's console. "
               "s3vault can't remove them.");
        bullet("Export the new key file and keep it with the new recovery key.");
        ImGui::Dummy(ImVec2(0, 4));
        int b = sheet_buttons("Export New Key File…", "Done");
        if (b == 1) {
            reset(a);
            a.modal = "export-key";
        } else if (b == 2) {
            close_wizard(a);
        }
        return;
    }
    if (r.result.paused) {
        std::string sub = p.total ? trf("%d of %d files are done. Nothing is lost.", p.done, p.total)
                                  : std::string(tr("Paused before any file was re-encrypted. Nothing is lost."));
        sheet_title(ICON_FA_PAUSE, P.orange, "Key Replacement Paused", sub.c_str());
    } else {
        sheet_title(ICON_FA_TRIANGLE_EXCLAMATION, P.red, "Key Replacement Didn't Finish", nullptr);
        ImGui::PushTextWrapPos(0);
        ImGui::TextColored(P.red, "%s", r.result.error.c_str());
        ImGui::PopTextWrapPos();
    }
    if (r.result.rotating) {
        para("Finish it with the NEW password: Settings › Finish key replacement. Until then, other devices stay locked and "
             "encrypted files don't sync.", P.dim);
        int b = sheet_buttons("Resume…", "Close");
        if (b == 1) open_rotation_resume(a);
        else if (b == 2) close_wizard(a);
    } else {
        para("Nothing was changed on the server.", P.dim);
        if (sheet_buttons(nullptr, "Close") == 2) close_wizard(a);
    }
}

static void draw_resume_form(App& a) {
    App::Rotation& r = a.rot;
    std::string sub = r.server_device.empty()
                          ? std::string(tr("A key replacement isn't finished. Other devices stay locked until it is."))
                          : trf("A key replacement started on %s isn't finished. Other devices stay locked until it is.",
                                r.server_device.c_str());
    sheet_title(ICON_FA_ARROWS_ROTATE, P.orange, "Finish Replacing the Vault Key", sub.c_str());
    sheet_field("New password (chosen when the replacement started)", a.pw1, sizeof a.pw1, "", true, true);
    if (!a.modal_error.empty()) ImGui::TextColored(P.red, "%s", a.modal_error.c_str());
    small_dim("%s", tr("Files already re-encrypted are checked and skipped."));
    int b = sheet_buttons("Resume", "Cancel", a.pw1[0] != 0);
    if (b == 1) {
        r.new_pw.assign(a.pw1);
        wipe_buf(a.pw1, sizeof a.pw1);
        r.resume = true;
        start_run(a);
    } else if (b == 2) {
        close_wizard(a);
    }
}

void rotation_script(App& a, const std::string& arg) {
    const char* old_pw = getenv("S3VAULT_PASSWORD");
    const char* new_pw = getenv("S3VAULT_NEW_PASSWORD");
    if (arg == "open") {
        open_rotation(a);
    } else if (starts_with(arg, "step=")) {
        int n = atoi(arg.c_str() + 5);
        App::Rotation& r = a.rot;
        r.ack = true;
        if (n >= 2 && r.key.empty()) {
            r.key.assign(Vault::new_vault_key());
            if (old_pw) r.old_pw.assign(old_pw);
            if (new_pw) r.new_pw.assign(new_pw);
            r.key_saved = true;
        }
        if (n >= 3) {
            std::string k(r.key.view());
            snprintf(r.confirm, sizeof r.confirm, "%s", k.substr(k.size() - 8).c_str());
            wipe(k);
            snprintf(r.go, sizeof r.go, "ROTATE");
        }
        r.step = n;
        a.modal = "rotate-key";
    } else if (arg == "run") {
        if (a.rot.key.empty()) rotation_script(a, "step=3");
        start_run(a);
        a.modal = "rotate-key";
    } else if (arg == "resume") {
        open_rotation_resume(a);
        if (new_pw) {
            a.rot.new_pw.assign(new_pw);
            start_run(a);
        }
    } else if (arg == "pause") {
        a.rot.cancel = true;
    }
}

void draw_rotation_sheets(App& a) {
    if (!sheet_begin(a.modal, "rotate-key", 580)) return;
    if (!a.vault) {
        close_wizard(a);
    } else {
        switch (a.rot.step) {
            case 0: draw_impact(a); break;
            case 1: draw_passwords(a); break;
            case 2: draw_new_key(a); break;
            case 3: draw_final(a); break;
            case 4: draw_running(a); break;
            case 5: draw_finished(a); break;
            default: draw_resume_form(a); break;
        }
    }
    sheet_end();
}

}  // namespace s3v::ui
