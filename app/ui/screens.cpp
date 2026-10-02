// Full-window states: the setup assistant (connect storage → create the vault → first synced folder) and the
// lock screen (window locked while sync runs, or the vault key is needed).
#include <GLFW/glfw3.h>

#include <algorithm>
#include <cstring>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "imgui.h"
#include "util/fs.h"
#include "util/secure.h"
#include "util/strings.h"

namespace s3v::ui {

void storage_fields(App& a);  // settings_view.cpp

static void hero(const char* icon, const ImVec4& c, const char* title, const char* sub) {
    float base = ImGui::GetStyle().FontSizeBase;
    float w = ImGui::GetContentRegionAvail().x;
    auto centre = [&](const char* t, float scale, const ImVec4& colr) {
        ImGui::PushFont(nullptr, base * scale);
        float tw = ImGui::CalcTextSize(t).x;
        if (tw < w) {
            ImGui::SetCursorPosX((w - tw) / 2);
            ImGui::TextColored(colr, "%s", t);
        } else {
            ImGui::PushStyleColor(ImGuiCol_Text, colr);
            ImGui::TextWrapped("%s", t);
            ImGui::PopStyleColor();
        }
        ImGui::PopFont();
    };
    centre(icon, 3.4f, c);
    ImGui::Dummy(ImVec2(0, 2));
    centre(title, 1.45f, P.text);
    if (sub && *sub) centre(sub, 0.95f, P.dim);
    ImGui::Dummy(ImVec2(0, 12));
}

static void steps(int cur) {
    const char* names[] = {"Storage", "Vault", "Folder"};
    float w = ImGui::GetContentRegionAvail().x;
    float total = 0;
    for (auto* n : names) total += ImGui::CalcTextSize(n).x + 40;
    ImGui::SetCursorPosX((w - total) / 2);
    for (int i = 0; i < 3; i++) {
        if (i) ImGui::SameLine(0, 10);
        ImVec4 c = i == cur ? P.accent : i < cur ? P.green : P.faint;
        ImGui::TextColored(c, "%s", i < cur ? ICON_FA_CIRCLE_CHECK : ICON_FA_CIRCLE);
        ImGui::SameLine(0, 6);
        ImGui::TextColored(i == cur ? P.text : P.dim, "%s", names[i]);
    }
    ImGui::Dummy(ImVec2(0, 10));
}

void draw_setup(App& a) {
    using C = App::Conn;
    ImGui::SetCursorPos(ImVec2(0, 0));
    ImGui::BeginChild("##setup", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_None);
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float colw = std::min(600.0f, avail.x - 40);
    ImGui::SetCursorPos(ImVec2((avail.x - colw) / 2, std::max(24.0f, avail.y * 0.08f)));
    ImGui::BeginChild("##col", ImVec2(colw, 0), ImGuiChildFlags_AutoResizeY, ImGuiWindowFlags_NoScrollbar);

    if (a.offer_first_folder && a.conn == C::Ready) {
        steps(2);
        hero(ICON_FA_FOLDER_OPEN, P.folder, "Keep a Folder in Sync?",
             "Pick a folder on this computer. It stays in sync with your vault, encrypted, in the background.");
        float bw = 200;
        ImGui::SetCursorPosX((colw - bw * 2 - 10) / 2);
        if (button("Not Now", Btn::Secondary, ImVec2(bw, 0))) a.offer_first_folder = false;
        ImGui::SameLine(0, 10);
        if (button("Choose Folder…", Btn::Primary, ImVec2(bw, 0))) {
            a.offer_first_folder = false;
            add_tracked_folder(a);
        }
    } else if (a.conn == C::NoVault) {
        steps(1);
        hero(ICON_FA_VAULT, P.accent, "Create Your Vault",
             "Choose a password. It protects the key that encrypts your files — there is no way to recover it if it's lost.");
        prefs::page_begin(colw);
        ImGui::BeginGroup();
        bool okpw = false;
        password_pair(a, okpw);
        if (!a.modal_error.empty()) ImGui::TextColored(P.red, "%s", a.modal_error.c_str());
        ImGui::Dummy(ImVec2(0, 8));
        if (a.modal_busy) {
            spinner(8, P.dim);
            ImGui::SameLine();
            ImGui::TextDisabled("Creating the vault…");
        } else {
            if (button("Create Vault", Btn::Primary, ImVec2(colw, 0), okpw && a.vault)) {
                std::string pw = a.pw1;
                secure_zero(a.pw1, sizeof a.pw1);
                secure_zero(a.pw2, sizeof a.pw2);
                auto v = a.vault;
                a.modal_busy = true;
                a.modal_error.clear();
                a.run_job([&a, v, pw]() mutable {
                    OpResult r = v->init(pw);
                    wipe(pw);
                    a.post([&a, r] {
                        a.modal_busy = false;
                        if (!r.ok) { a.modal_error = r.error; return; }
                        a.offer_first_folder = true;
                        connect_async(a);
                    });
                });
            }
            ImGui::Dummy(ImVec2(0, 2));
            float tw = ImGui::CalcTextSize("Continue Without a Password").x + 28;
            ImGui::SetCursorPosX((colw - tw) / 2);
            if (button("Continue Without a Password", Btn::Plain, ImVec2(tw, 0), a.vault != nullptr)) {
                auto v = a.vault;
                a.run_job([&a, v] {
                    OpResult r = v->init("");
                    a.post([&a, r] {
                        if (!r.ok) { a.modal_error = r.error; return; }
                        a.offer_first_folder = true;
                        connect_async(a);
                    });
                });
            }
            tip("Files are stored as they are until you set a password in Settings");
        }
        ImGui::EndGroup();
    } else {
        steps(0);
        hero(ICON_FA_VAULT, P.accent, "Welcome to s3vault", "Your files, synced and encrypted, on storage you own — Cloudflare R2, AWS S3, MinIO and more.");
        prefs::page_begin(colw);
        prefs::section("Your storage");
        prefs::card_begin();
        storage_fields(a);
        prefs::card_end();
        ImGui::Dummy(ImVec2(0, 10));
        if (a.conn == C::Error) {
            ImGui::PushStyleColor(ImGuiCol_Text, P.red);
            ImGui::TextWrapped(ICON_FA_CIRCLE_EXCLAMATION "  %s", a.conn_error.c_str());
            ImGui::PopStyleColor();
            ImGui::Dummy(ImVec2(0, 4));
        }
        if (a.conn == C::Connecting) {
            ImGui::SetCursorPosX(colw / 2 - 60);
            spinner(8, P.dim);
            ImGui::SameLine();
            ImGui::TextDisabled("Connecting…");
        } else {
            const StorageConfig& s = a.form.storage;
            bool complete = !s.bucket.empty() && !s.access_key_id.empty() && (s.provider != "r2" || !s.account_id.empty()) &&
                            (a.secret_buf[0] || getenv("S3VAULT_SECRET_KEY") || a.conn == C::Error);
            ImGui::SetCursorPosX(16);
            if (button("Continue", Btn::Primary, ImVec2(colw - 32, ImGui::GetFrameHeight() + 6), complete)) settings_connect(a);
            ImGui::SetCursorPosX(18);
            small_dim("Tip: use an API token limited to this bucket. The secret is kept in your keychain.");
        }
    }
    ImGui::EndChild();
    ImGui::EndChild();
}

// ---------------------------------------------------------------------------------------------------

void draw_lock_screen(App& a) {
    bool need_key = key_needed(a);  // otherwise: the window is locked but the key is loaded
    ImGui::SetCursorPos(ImVec2(0, 0));
    ImGui::BeginChild("##lock");
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float colw = std::min(380.0f, avail.x - 40);
    ImGui::SetCursorPos(ImVec2((avail.x - colw) / 2, avail.y * 0.22f));
    ImGui::BeginChild("##col", ImVec2(colw, 0), ImGuiChildFlags_AutoResizeY, ImGuiWindowFlags_NoScrollbar);
    std::string where = a.cfg.storage.bucket + " / " + a.cfg.storage.prefix;
    hero(ICON_FA_LOCK, P.dim, need_key ? "Unlock Your Vault" : "s3vault Is Locked", where.c_str());

    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, ImGui::GetFrameHeight() / 2);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(14, 7));
    ImGui::SetNextItemWidth(colw);
    if (!a.lock_busy && !ImGui::IsAnyItemActive() && a.modal.empty()) ImGui::SetKeyboardFocusHere();
    bool enter = ImGui::InputTextWithHint("##pw", "Vault password", a.lock_pw, sizeof a.lock_pw,
                                          ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::PopStyleVar(2);
    ImGui::Dummy(ImVec2(0, 4));
    bool go = button(a.lock_busy ? "Checking…" : "Unlock", Btn::Primary, ImVec2(colw, ImGui::GetFrameHeight() + 6), a.lock_pw[0] && !a.lock_busy);
    if ((go || (enter && a.lock_pw[0])) && !a.lock_busy && a.vault) {
        std::string pw = a.lock_pw;
        secure_zero(a.lock_pw, sizeof a.lock_pw);
        a.lock_busy = true;
        auto v = a.vault;
        a.run_job([&a, v, pw]() mutable {
            OpResult r = v->unlocked() ? v->verify_password(pw) : v->unlock(pw);
            wipe(pw);
            a.post([&a, r] {
                a.lock_busy = false;
                if (r.ok) {
                    a.ui_locked = false;
                    a.browse_locked = false;
                    a.lock_error.clear();
                    a.tree_dirty = true;
                    a.last_input = glfwGetTime();
                    if (a.engine) a.engine->request_sync();
                } else {
                    a.lock_error = r.bad_key ? "Wrong password. Try again." : r.error;
                }
            });
        });
    }
    if (!a.lock_error.empty()) {
        ImGui::Dummy(ImVec2(0, 2));
        float tw = ImGui::CalcTextSize(a.lock_error.c_str()).x;
        ImGui::SetCursorPosX(std::max(0.0f, (colw - tw) / 2));
        ImGui::TextColored(P.red, "%s", a.lock_error.c_str());
    }
    ImGui::Dummy(ImVec2(0, 14));
    // Sync status: no file content, so it may show while locked.
    {
        std::string s;
        ImVec4 c = P.dim;
        size_t nx = a.engine ? a.engine->transfers().size() : 0;
        if (need_key) s = ICON_FA_PAUSE "  Encrypted files wait until you unlock";
        else if (a.engine && a.engine->syncing()) { s = ICON_FA_ROTATE "  Syncing in the background" + (nx ? " · " + std::to_string(nx) + " files" : std::string()); c = P.green; }
        else if (a.engine && a.engine->last_sync()) s = ICON_FA_CIRCLE_CHECK "  Sync keeps running · checked " + format_local_time(a.engine->last_sync()).substr(11);
        float tw = ImGui::CalcTextSize(s.c_str()).x;
        ImGui::SetCursorPosX(std::max(0.0f, (colw - tw) / 2));
        ImGui::TextColored(c, "%s", s.c_str());
        if (a.edits && a.edits->any_dirty()) {
            std::string e = ICON_FA_PEN "  Unsaved editor changes are kept";
            tw = ImGui::CalcTextSize(e.c_str()).x;
            ImGui::SetCursorPosX(std::max(0.0f, (colw - tw) / 2));
            ImGui::TextColored(P.orange, "%s", e.c_str());
        }
    }
    ImGui::Dummy(ImVec2(0, 10));
    const char* alt = need_key ? "Browse Without Unlocking" : "Forget the Key and Stop Syncing";
    float aw = ImGui::CalcTextSize(alt).x + 28;
    ImGui::SetCursorPosX((colw - aw) / 2);
    if (button(alt, Btn::Plain, ImVec2(aw, 0))) {
        if (need_key) a.browse_locked = true;
        else forget_key(a);
    }
    tip(need_key ? "See file names; encrypted contents stay locked and don't sync" : "Encrypted files stop syncing until you unlock again");
    ImGui::EndChild();
    ImGui::EndChild();
}

}  // namespace s3v::ui
