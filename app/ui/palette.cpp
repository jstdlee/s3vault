// Feature search (Ctrl+P or Ctrl+K, or the magnifier at the top of the sidebar): type a few letters of any view, action or
// setting — in English or the UI language — and Enter goes there. A setting is scrolled into view and briefly
// highlighted. The palette itself opens and closes without animation: it is a keyboard tool used all day.
#include <GLFW/glfw3.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "util/strings.h"

namespace s3v::ui {

namespace {

struct Feature {
    const char* icon;
    const char* title;     // English; shown translated
    const char* kind;      // "Go to", "Action", or the Settings section
    const char* keywords;  // extra English words that should find it
    std::function<void(App&)> run;
};

bool g_open = false, g_focus = false;
char g_query[128];
int g_sel = 0;

void locate(App& a, const char* title, bool advanced = false) {
    if (advanced && !a.cfg.ui.advanced) {
        a.cfg.ui.advanced = 1;
        save_settings(a);
    }
    set_view(a, View::Settings);
    prefs::locate(title);
}

void set_theme(App& a, const char* t) {
    a.cfg.ui.theme = t;
    save_settings(a);
}

const std::vector<Feature>& features();

// Glossary terms from Help, so "what is a bucket" finds its definition.
const std::vector<Feature>& all_features() {
    static std::vector<Feature> all = [] {
        std::vector<Feature> v = features();
        for (auto& [term, def] : help_topics()) {
            const char* t = term;
            v.push_back({ICON_FA_BOOK, t, "Glossary", def, [t](App& a) { open_help(a, 1, t); }});
        }
        return v;
    }();
    return all;
}

const std::vector<Feature>& features() {
    static const std::vector<Feature> f = {
        // Views
        {ICON_FA_HARD_DRIVE, "All Files", "Go to", "vault browse home files list", [](App& a) { navigate(a, ""); }},
        {ICON_FA_TRASH, "Trash", "Go to", "deleted restore put back", [](App& a) { set_view(a, View::Trash); }},
        {ICON_FA_ARROW_RIGHT_ARROW_LEFT, "Transfers", "Go to", "uploads downloads progress activity log queue",
         [](App& a) { set_view(a, View::Transfers); }},
        {ICON_FA_CODE_MERGE, "Conflicts", "Go to", "resolve both changed keep", [](App& a) { set_view(a, View::Conflicts); }},
        {ICON_FA_PEN_TO_SQUARE, "Editor", "Go to", "open files edit text", [](App& a) { set_view(a, View::Editor); }},
        {ICON_FA_GEAR, "Settings", "Go to", "preferences options configuration", [](App& a) { set_view(a, View::Settings); }},
        // Actions
        {ICON_FA_CLOUD_ARROW_UP, "Upload files or folders", "Action", "add put send",
         [](App& a) { set_view(a, View::Files); choose_and_upload(a); }},
        {ICON_FA_FOLDER_PLUS, "New Folder", "Action", "create directory mkdir",
         [](App& a) { set_view(a, View::Files); a.text_buf[0] = 0; a.modal = "new-folder"; }},
        {ICON_FA_WAND_MAGIC_SPARKLES, "Sync a folder", "Action", "track add synced folder watch keep", [](App& a) { add_tracked_folder(a); }},
        {ICON_FA_CIRCLE_QUESTION, "Help", "Help", "concepts guide manual", [](App& a) { open_help(a, 0); }},
        {ICON_FA_KEYBOARD, "Keyboard shortcuts", "Help", "keys hotkeys", [](App& a) { open_help(a, 2); }},
        {ICON_FA_BOOK, "Glossary", "Help", "terms words meaning", [](App& a) { open_help(a, 1); }},
        {ICON_FA_LIST_CHECK, "Tasks and activity log", "Action", "queue progress logs status cancel pause", [](App& a) { toggle_status(a); }},
        {ICON_FA_CIRCLE_HALF_STROKE, "Switch theme", "Action", "theme appearance tokyo night dark light", [](App& a) {
             static const char* order[] = {"system", "light", "dark", "tokyo"};
             int i = 0;
             for (int k = 0; k < 4; k++)
                 if (a.cfg.ui.theme == order[k]) i = k;
             set_theme(a, order[(i + 1) % 4]);
         }},
        {ICON_FA_TABLE_COLUMNS, "Show or hide the sidebar", "Action", "panel navigation", [](App& a) { a.sidebar_hidden = !a.sidebar_hidden; }},
        {ICON_FA_ROTATE, "Sync now", "Action", "refresh check update", [](App& a) { if (a.engine) a.engine->request_sync(); refresh_listing(a); }},
        {ICON_FA_LOCK, "Lock the window", "Action", "hide privacy away", [](App& a) { lock_ui(a, nullptr); }},
        {ICON_FA_KEY, "Change Vault Password", "Action", "passphrase password security",
         [](App& a) { a.modal = a.vault_has_key ? "change-password" : "set-password"; }},
        {ICON_FA_FILE_EXPORT, "Export Key", "Action", "backup recovery key file", [](App& a) { a.modal = "export-key"; }},
        {ICON_FA_DOWNLOAD, "Download everything", "Action", "backup decrypted export all", [](App& a) { start_download_all(a, true); }},
        {ICON_FA_BOX_ARCHIVE, "Download everything, as stored", "Action", "backup encrypted export all",
         [](App& a) { start_download_all(a, false); }},
        {ICON_FA_TRASH_CAN, "Empty Trash…", "Action", "purge delete forever", [](App& a) { set_view(a, View::Trash); a.modal = "empty-trash"; }},
        {ICON_FA_CIRCLE_INFO, "Show or hide the inspector", "Action", "details info panel preview",
         [](App& a) { a.cfg.ui.inspector = !a.cfg.ui.inspector; save_settings(a); set_view(a, View::Files); }},
        {ICON_FA_MOON, "Dark appearance", "Action", "theme night black", [](App& a) { set_theme(a, "dark"); }},
        {ICON_FA_SUN, "Light appearance", "Action", "theme day white", [](App& a) { set_theme(a, "light"); }},
        {ICON_FA_MOON, "Tokyo Night appearance", "Action", "theme night blue purple", [](App& a) { set_theme(a, "tokyo"); }},
        // Settings rows (English titles exactly as in settings_view.cpp)
        {ICON_FA_CLOUD, "Provider", "Storage", "r2 cloudflare aws s3 minio b2 wasabi", [](App& a) { locate(a, "Provider"); }},
        {ICON_FA_CLOUD, "Bucket", "Storage", "storage", [](App& a) { locate(a, "Bucket"); }},
        {ICON_FA_CLOUD, "Vault folder", "Storage", "prefix path", [](App& a) { locate(a, "Vault folder"); }},
        {ICON_FA_CLOUD, "Access key ID", "Storage", "api token credentials", [](App& a) { locate(a, "Access key ID"); }},
        {ICON_FA_CLOUD, "Secret access key", "Storage", "api token credentials", [](App& a) { locate(a, "Secret access key"); }},
        {ICON_FA_PLUG, "Status", "Storage", "connection connected test reconnect", [](App& a) { locate(a, "Status"); }},
        {ICON_FA_SHIELD_HALVED, "Vault password", "Security", "passphrase change", [](App& a) { locate(a, "Vault password"); }},
        {ICON_FA_SHIELD_HALVED, "Lock after", "Security", "idle timeout auto lock minutes", [](App& a) { locate(a, "Lock after"); }},
        {ICON_FA_SHIELD_HALVED, "Remember the key", "Security", "keychain cache unlock", [](App& a) { locate(a, "Remember the key"); }},
        {ICON_FA_SHIELD_HALVED, "Forget the key now", "Security", "lock key", [](App& a) { locate(a, "Forget the key now"); }},
        {ICON_FA_FOLDER, "Direction", "Synced folders", "two-way backup mirror upload only", [](App& a) { locate(a, "Direction"); }},
        {ICON_FA_FOLDER, "Encrypt new files", "Synced folders", "plain gpg", [](App& a) { locate(a, "Encrypt new files"); }},
        {ICON_FA_FOLDER, "Pause", "Synced folders", "stop resume", [](App& a) { locate(a, "Pause"); }},
        {ICON_FA_ROTATE, "Check the server", "Sync", "interval poll frequency", [](App& a) { locate(a, "Check the server"); }},
        {ICON_FA_ROTATE, "Files at once", "Sync", "parallel concurrency threads", [](App& a) { locate(a, "Files at once"); }},
        {ICON_FA_ROTATE, "Speed limit", "Sync", "bandwidth throttle", [](App& a) { locate(a, "Speed limit"); }},
        {ICON_FA_ROTATE, "Keep deleted files", "Sync", "trash retention days", [](App& a) { locate(a, "Keep deleted files"); }},
        {ICON_FA_ROTATE, "This device", "Sync", "device name computer hostname", [](App& a) { locate(a, "This device"); }},
        {ICON_FA_PALETTE, "Appearance", "Appearance", "theme dark light system", [](App& a) { locate(a, "Appearance"); }},
        {ICON_FA_LANGUAGE, "Language", "Appearance", "english chinese japanese korean 中文 日本語 한국어 locale", [](App& a) { locate(a, "Language"); }},
        {ICON_FA_FONT, "Text size", "Appearance", "font zoom scale bigger smaller", [](App& a) { locate(a, "Text size"); }},
        {ICON_FA_WIND, "Motion", "Appearance", "animation reduce motion accessibility", [](App& a) { locate(a, "Motion"); }},
        {ICON_FA_SLIDERS, "Show advanced settings", "Appearance", "advanced", [](App& a) { locate(a, "Show advanced settings"); }},
        {ICON_FA_LOCK, "Encryption program", "Advanced", "gpg gnupg gpg4win", [](App& a) { locate(a, "Encryption program", true); }},
        {ICON_FA_FILE_PDF, "PDF previews", "Advanced", "pdftoppm poppler", [](App& a) { locate(a, "PDF previews", true); }},
        {ICON_FA_KEY, "Keychain", "Advanced", "secret service credential manager", [](App& a) { locate(a, "Keychain", true); }},
        {ICON_FA_FILE_LINES, "Text preview limit (MB)", "Advanced", "size", [](App& a) { locate(a, "Text preview limit (MB)", true); }},
        {ICON_FA_FILE_IMAGE, "Image preview limit (MB)", "Advanced", "size", [](App& a) { locate(a, "Image preview limit (MB)", true); }},
        {ICON_FA_FILE, "Settings file", "Advanced", "config ini path", [](App& a) { locate(a, "Settings file", true); }},
    };
    return f;
}

bool contains_ci(const std::string& hay, const std::string& needle) { return to_lower(hay).find(needle) != std::string::npos; }

// Higher is better; <0 = no match. Matches the shown (translated) title, the English title, the place and keywords.
int score(const Feature& f, const std::string& q) {
    if (q.empty()) return 1;
    std::string shown = tr(f.title);
    std::string t = to_lower(shown), e = to_lower(f.title);
    if (t.rfind(q, 0) == 0 || e.rfind(q, 0) == 0) return 100;
    if (t.find(q) != std::string::npos || e.find(q) != std::string::npos) return 60;
    if (contains_ci(tr(f.kind), q) || contains_ci(f.kind, q)) return 30;
    // every word of the query somewhere in the keywords
    std::string kw = to_lower(std::string(f.keywords) + " " + f.title + " " + shown);
    for (auto& w : split(q, ' '))
        if (!w.empty() && kw.find(w) == std::string::npos) return -1;
    return 20;
}

}  // namespace

void open_palette(App& a, const char* query) {
    (void)a;
    g_open = true;
    g_focus = true;
    snprintf(g_query, sizeof g_query, "%s", query ? query : "");
    g_sel = 0;
}

void draw_palette(App& a) {
    if (!g_open) return;
    if (!ImGui::IsPopupOpen("##palette")) ImGui::OpenPopup("##palette");
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    float w = std::min(580.0f, vp->WorkSize.x - 40);
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + vp->WorkSize.x / 2, vp->WorkPos.y + vp->WorkSize.y * 0.14f), ImGuiCond_Always, ImVec2(0.5f, 0));
    ImGui::SetNextWindowSize(ImVec2(w, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10, 10));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12);
    ImGui::PushStyleColor(ImGuiCol_PopupBg, P.card);
    bool shown = ImGui::BeginPopup("##palette", ImGuiWindowFlags_NoMove | ImGuiWindowFlags_AlwaysAutoResize);
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(2);
    if (!shown) {  // closed by a click outside
        g_open = false;
        return;
    }

    // Query field: a large search box.
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 1.15f);
    if (g_focus) {
        ImGui::SetKeyboardFocusHere();
        g_focus = false;
    }
    std::string before = g_query;
    search_field("##pq", g_query, sizeof g_query, w - 20, "Find a feature or setting");
    ImGui::PopFont();
    if (before != g_query) g_sel = 0;

    std::string q = to_lower(trim(g_query));
    std::vector<std::pair<int, const Feature*>> hits;
    for (auto& f : all_features())
        if (int s = score(f, q); s >= 0 && (!q.empty() || strcmp(f.kind, "Glossary") != 0)) hits.push_back({s, &f});
    std::stable_sort(hits.begin(), hits.end(), [](auto& x, auto& y) { return x.first > y.first; });
    if (q.empty()) hits.resize(std::min<size_t>(hits.size(), 8));
    else if (hits.size() > 12) hits.resize(12);

    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) g_sel = std::min(int(hits.size()) - 1, g_sel + 1);
    if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) g_sel = std::max(0, g_sel - 1);
    const Feature* run = nullptr;
    if ((ImGui::IsKeyPressed(ImGuiKey_Enter) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter)) && !hits.empty())
        run = hits[size_t(std::clamp(g_sel, 0, int(hits.size()) - 1))].second;

    ImGui::Dummy(ImVec2(0, 4));
    if (hits.empty()) {
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 8);
        small_dim("No Results");
        ImGui::Dummy(ImVec2(0, 4));
    }
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float rh = ImGui::GetFrameHeight() + 8;
    for (size_t i = 0; i < hits.size(); i++) {
        const Feature& f = *hits[i].second;
        ImVec2 p = ImGui::GetCursorScreenPos();
        ImGui::PushID(int(i));
        bool click = ImGui::InvisibleButton("##hit", ImVec2(w - 20, rh));
        bool hov = ImGui::IsItemHovered();
        ImGui::PopID();
        if (hov && ImGui::GetIO().MouseDelta.x + ImGui::GetIO().MouseDelta.y != 0) g_sel = int(i);
        if (click) run = &f;
        bool on = int(i) == g_sel;
        if (on) dl->AddRectFilled(p, ImVec2(p.x + w - 20, p.y + rh), col(P.select), 7);
        float ty = p.y + (rh - ImGui::GetTextLineHeight()) / 2;
        dl->AddText(ImVec2(p.x + 12, ty), col(on ? P.accent : P.dim), f.icon);
        dl->AddText(ImVec2(p.x + 40, ty), col(P.text), tr(f.title));
        const char* kind = tr(f.kind);
        ImVec2 ks = ImGui::CalcTextSize(kind);
        dl->AddText(ImVec2(p.x + w - 32 - ks.x, ty), col(P.dim), kind);
        if (const char* keys = shortcut_for(f.title)) {  // the command's shortcut, as key chips, left of its kind
            ImVec2 save = ImGui::GetCursorScreenPos();
            float kw = 0;
            for (const char* c = keys; *c; c++) kw += *c == '+' ? 6 : 0;
            kw += ImGui::CalcTextSize(keys).x * 0.82f + 24;
            ImGui::SetCursorScreenPos(ImVec2(p.x + w - 48 - ks.x - kw, p.y + (rh - ImGui::GetTextLineHeight() - 3) / 2));
            key_chips(keys);
            ImGui::SetCursorScreenPos(save);
        }
    }
    ImGui::Dummy(ImVec2(0, 2));
    small_dim("↑↓ to choose · Enter to open · Esc to close");

    if (ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        g_open = false;
        ImGui::CloseCurrentPopup();
    }
    if (run) {
        g_open = false;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
    if (run) run->run(a);
}

}  // namespace s3v::ui
