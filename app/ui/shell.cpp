// App shell (polish-app): the utility cluster at the top right — search, status · tasks · logs, help, settings —
// its status popover, the Help window (concepts, glossary, shortcuts) and the keymap registry they read.
#include <GLFW/glfw3.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <string>
#include <vector>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "imgui_internal.h"
#include "util/strings.h"

namespace s3v::ui {

// ---------------------------------------------------------------------------------------------------
// keymap registry (Help › Shortcuts and the palette read it; global_shortcuts() in app.cpp handles the keys)

const std::vector<Shortcut>& shortcuts() {
    static const std::vector<Shortcut> k = {
        {"Ctrl+P", "Find a feature or setting", "General"},
        {"F1", "Help", "General"},
        {"Ctrl+/", "Keyboard shortcuts", "General"},
        {"Ctrl+,", "Settings", "General"},
        {"Ctrl+J", "Tasks and activity log", "General"},
        {"Ctrl+Shift+T", "Switch theme", "View"},
        {"Ctrl+B", "Show or hide the sidebar", "View"},
        {"Ctrl+I", "Show or hide the inspector", "View"},
        {"Ctrl+= / Ctrl+- / Ctrl+0", "Text size: larger / smaller / reset", "View"},
        {"F11", "Maximize or restore the window", "View"},
        {"Alt+← / Alt+→", "Back / forward", "Navigation"},
        {"Backspace", "Enclosing folder", "Navigation"},
        {"Ctrl+F", "Search the vault", "Navigation"},
        {"Enter / F2", "Rename", "Files"},
        {"Space", "Quick Look", "Files"},
        {"Ctrl+E", "Open in the editor", "Files"},
        {"Ctrl+U", "Upload files or folders", "Files"},
        {"Ctrl+Shift+N", "New Folder", "Files"},
        {"Delete", "Move to Trash", "Files"},
        {"Ctrl+A", "Select All", "Files"},
        {"Ctrl+R / F5", "Refresh", "Files"},
        {"Ctrl+Shift+A", "Sync a folder", "Files"},
        {"Ctrl+S", "Save", "Editor"},
        {"Esc", "Close a sheet, the palette or Help", "General"},
        {"Ctrl+Q", "Quit", "General"},
    };
    return k;
}

const char* shortcut_for(const char* action) {
    for (auto& s : shortcuts())
        if (!strcmp(s.action, action)) return s.keys;
    return nullptr;
}

// ---------------------------------------------------------------------------------------------------
// utility cluster

namespace {

constexpr float kBtn = 30, kGap = 4;
bool g_status_open = false;
int g_status_tab = 0;  // 0 tasks, 1 logs
bool g_help_open = false;
int g_help_tab = 0;
char g_help_q[96];
std::string g_help_focus;  // glossary term to scroll to
int g_log_filter = 0;      // 0 all, 1 errors, 2 warnings
char g_log_q[96];
bool g_cancelling = false;

// Overall progress, weighted by bytes.
void overall(App& a, size_t& n, size_t& running, float& f) {
    n = running = 0;
    f = 0;
    if (!a.engine) return;
    uint64_t done = 0, total = 0;
    for (auto& t : a.engine->transfers()) {
        n++;
        if (!t.queued) running++;
        done += std::min(t.done, t.total);
        total += t.total;
    }
    f = total ? float(double(done) / double(total)) : 0.0f;
}

int log_level(const std::string& l) {
    std::string s = to_lower(l);
    if (s.find("failed") != std::string::npos || s.find("error") != std::string::npos || s.find("can't") != std::string::npos) return 1;
    if (s.find("conflict") != std::string::npos || s.find("skipped") != std::string::npos || s.find("warning") != std::string::npos) return 2;
    return 0;
}

}  // namespace

float utility_cluster_width() { return 4 * kBtn + 3 * kGap + 14; }

void toggle_status(App& a) {
    (void)a;
    g_status_open = !g_status_open;
}

void open_status(App& a, int tab) {
    (void)a;
    g_status_open = true;
    g_status_tab = tab;
}

void open_help(App& a, int tab, const char* term) {
    (void)a;
    g_help_open = true;
    g_help_tab = tab;
    g_help_focus = term ? term : "";
    g_help_q[0] = 0;
}

void draw_utility_cluster(App& a) {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    float w = utility_cluster_width();
    ImVec2 pos(vp->Pos.x + vp->Size.x - window_buttons_width() - w, vp->Pos.y + 11);
    ImGui::SetNextWindowPos(pos);
    ImGui::SetNextWindowSize(ImVec2(w, kBtn + 4));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##cluster", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoSavedSettings |
                     ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoNav);
    ImGui::PopStyleVar();
    bool locked = a.ui_locked;

    // 1 search
    ImGui::SetCursorPos(ImVec2(0, 2));
    if (icon_button(ICON_FA_MAGNIFYING_GLASS, "Find a feature or setting  (Ctrl+P)", false, !locked, kBtn)) open_palette(a);
    // first-run tip, once
    if (!a.cfg.ui.tip_palette && !locked && a.conn == App::Conn::Ready) {
        ImVec2 r = ImGui::GetItemRectMin();
        ImGui::SetNextWindowPos(ImVec2(r.x + kBtn / 2, r.y + kBtn + 8), ImGuiCond_Always, ImVec2(0.5f, 0));
        ImGui::PushStyleColor(ImGuiCol_WindowBg, P.accent);
        ImGui::PushStyleColor(ImGuiCol_Text, P.on_accent);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 8);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12, 8));
        ImGui::Begin("##tip", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings |
                                            ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav);
        ImGui::AlignTextToFramePadding();
        ImGui::TextUnformatted(tr("Press Ctrl+P to find anything"));
        ImGui::SameLine(0, 8);
        {  // ✕ in the tip's own ink, a faint square on hover
            float s = ImGui::GetFrameHeight();
            ImVec2 bp = ImGui::GetCursorScreenPos();
            if (ImGui::InvisibleButton("##tipx", ImVec2(s, s))) { a.cfg.ui.tip_palette = 1; save_settings(a); }
            ImDrawList* tdl = ImGui::GetWindowDrawList();
            if (ImGui::IsItemHovered()) tdl->AddRectFilled(bp, ImVec2(bp.x + s, bp.y + s), col(P.on_accent, 0.18f), 6);
            ImVec2 xs = ImGui::CalcTextSize(ICON_FA_XMARK);
            tdl->AddText(ImVec2(bp.x + (s - xs.x) / 2, bp.y + (s - xs.y) / 2), col(P.on_accent), ICON_FA_XMARK);
            tip("Don't show again");
        }
        ImGui::End();
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(2);
    }

    // 2 status · tasks · logs: a progress ring around the icon and a count badge while work runs
    ImGui::SameLine(0, kGap);
    size_t n, running;
    float f;
    overall(a, n, running, f);
    ImVec2 p = ImGui::GetCursorScreenPos();
    std::string tipline = n ? trf("%d of %d · %d %%", int(running), int(n), int(std::lround(f * 100))) + "  (Ctrl+J)"
                            : std::string(tr("Tasks and activity log")) + "  (Ctrl+J)";
    if (icon_button(ICON_FA_LIST_CHECK, tipline.c_str(), g_status_open, true, kBtn)) toggle_status(a);
    if (n) {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 c(p.x + kBtn / 2, p.y + kBtn / 2);
        float r = kBtn / 2 - 2;
        dl->PathArcTo(c, r, 0, 2 * IM_PI, 32);
        dl->PathStroke(col(P.track), 0, 2.0f);
        if (f > 0) {
            dl->PathArcTo(c, r, -IM_PI / 2, -IM_PI / 2 + 2 * IM_PI * std::clamp(f, 0.0f, 1.0f), 32);
            dl->PathStroke(col(P.accent), 0, 2.0f);
        }
        std::string b = n > 99 ? "99+" : std::to_string(n);
        ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 0.68f);
        ImVec2 ts = ImGui::CalcTextSize(b.c_str());
        float bw = std::max(ts.y + 2, ts.x + 6);
        ImVec2 b0(p.x + kBtn - bw + 3, p.y - 1);
        dl->AddRectFilled(b0, ImVec2(b0.x + bw, b0.y + ts.y + 2), col(P.accent), (ts.y + 2) / 2);
        dl->AddText(ImVec2(b0.x + (bw - ts.x) / 2, b0.y + 1), col(P.on_accent), b.c_str());
        ImGui::PopFont();
    }

    // 3 help
    ImGui::SameLine(0, kGap);
    if (icon_button(ICON_FA_CIRCLE_QUESTION, "Help  (F1)", g_help_open, true, kBtn)) open_help(a, 0);
    // 4 settings
    ImGui::SameLine(0, kGap);
    if (icon_button(ICON_FA_GEAR, "Settings  (Ctrl+,)", a.view == View::Settings, !locked, kBtn)) set_view(a, View::Settings);
    // divider before the window buttons
    ImVec2 e = ImGui::GetItemRectMax();
    ImGui::GetWindowDrawList()->AddLine(ImVec2(e.x + 8, e.y - kBtn + 7), ImVec2(e.x + 8, e.y - 7), col(P.divider));
    ImGui::End();
}

// ---------------------------------------------------------------------------------------------------
// status popover: Tasks and Logs

void draw_status_popover(App& a) {
    if (g_cancelling && a.engine && a.engine->transfers().empty()) {
        if (a.vault && a.vault->connected()) a.vault->s3().cancel = false;
        g_cancelling = false;
    }
    if (!g_status_open) return;
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    float w = std::min(440.0f, vp->Size.x - 40);
    ImGui::SetNextWindowPos(ImVec2(vp->Pos.x + vp->Size.x - window_buttons_width() - 12, vp->Pos.y + 48), ImGuiCond_Always, ImVec2(1, 0));
    ImGui::SetNextWindowSize(ImVec2(w, 0));
    ImGui::SetNextWindowSizeConstraints(ImVec2(w, 120), ImVec2(w, std::min(520.0f, vp->Size.y - 80)));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, P.card);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14, 12));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1);
    ImGui::Begin("##statuspop", &g_status_open,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_AlwaysAutoResize);
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor();

    size_t n, running;
    float f;
    overall(a, n, running, f);
    // Header: one sentence about the app's state
    std::string head = a.conn != App::Conn::Ready ? tr("Not connected")
                       : n                          ? trf("Syncing %s", tr_n(n, "%zu file", "%zu files").c_str())
                       : (a.engine && a.engine->syncing()) ? tr("Checking for changes")
                                                           : tr("Up to date");
    title_text(head.c_str(), 1.05f);
    ImGui::SameLine();
    ImGui::SetCursorPosX(ImGui::GetWindowContentRegionMax().x - prefs::seg_width({"Tasks", "Logs"}));
    prefs::seg("##sttab", &g_status_tab, {"Tasks", "Logs"});
    ImGui::Dummy(ImVec2(0, 4));

    float inner = w - 28;
    if (g_status_tab == 0) {
        if (n) {
            progress(f, inner, 5);
            small_dim("%s", trf("%d of %d · %d %%", int(running), int(n), int(std::lround(f * 100))).c_str());
        }
        auto roots = a.db.roots();
        bool any_paused = false, any_running = false;
        for (auto& r : roots) (r.paused ? any_paused : any_running) = true;
        if (!roots.empty()) {
            if (any_running && button(ICON_FA_PAUSE "  Pause all", Btn::Secondary)) {
                for (auto r : roots) { r.paused = true; a.db.update_root(r); }
            }
            if (any_running) ImGui::SameLine();
            if (any_paused && button(ICON_FA_PLAY "  Resume all", Btn::Secondary)) {
                for (auto r : roots) { r.paused = false; a.db.update_root(r); }
                if (a.engine) a.engine->request_sync();
            }
            if (any_paused) ImGui::SameLine();
        }
        if (button(ICON_FA_XMARK "  Cancel all", Btn::Destructive, ImVec2(0, 0), n > 0 && !g_cancelling) && a.vault && a.vault->connected()) {
            a.vault->s3().cancel = true;  // in-flight transfers stop now; sync picks them up again on its next pass
            g_cancelling = true;
            if (a.engine) a.engine->log("Cancelled the transfers in progress");
        }
        tip("Transfers stop now; the next sync pass tries them again");
        ImGui::Dummy(ImVec2(0, 4));
        if (!n) {
            small_dim("Nothing is transferring");
        } else {
            ImGui::BeginChild("##tasks", ImVec2(inner, std::min(300.0f, float(n) * 44 + 4)));
            for (auto& t : a.engine->transfers()) {
                const char* icon = t.what == "upload" ? ICON_FA_ARROW_UP : t.what == "download" ? ICON_FA_ARROW_DOWN : ICON_FA_CODE_COMPARE;
                ImGui::TextColored(t.queued ? P.dim : P.accent, "%s", icon);
                ImGui::SameLine(0, 10);
                ImGui::BeginGroup();
                std::string name = path_basename(t.path);
                ImGui::TextUnformatted(name.c_str());
                if (t.queued) small_dim("Waiting · %s", human_size(t.total).c_str());
                else {
                    progress(t.total ? float(double(t.done) / double(t.total)) : 0.0f, inner - 40, 4);
                    small_dim("%s of %s", human_size(t.done).c_str(), human_size(t.total).c_str());
                }
                ImGui::EndGroup();
                tip(t.path);
            }
            ImGui::EndChild();
        }
    } else {
        // Logs: newest first, level chips, search, copy
        prefs::seg("##lvl", &g_log_filter, {"All", "Errors", "Warnings"});
        ImGui::Dummy(ImVec2(0, 2));
        search_field("##logq", g_log_q, sizeof g_log_q, inner - 92, "Filter");
        ImGui::SameLine(0, 8);
        std::vector<std::string> lines = a.engine ? a.engine->log_lines(500) : std::vector<std::string>{};
        std::string q = to_lower(trim(g_log_q));
        std::vector<std::string> shown;
        for (auto it = lines.rbegin(); it != lines.rend(); ++it) {
            int lv = log_level(*it);
            if (g_log_filter == 1 && lv != 1) continue;
            if (g_log_filter == 2 && lv != 2) continue;
            if (!q.empty() && to_lower(*it).find(q) == std::string::npos) continue;
            shown.push_back(*it);
        }
        if (button(ICON_FA_COPY "  Copy", Btn::Secondary, ImVec2(80, 0), !shown.empty())) {
            std::string all;
            for (auto& l : shown) all += l + "\n";
            glfwSetClipboardString(a.win, all.c_str());
            a.notify(tr("Copied"));
        }
        ImGui::Dummy(ImVec2(0, 2));
        ImGui::BeginChild("##logs", ImVec2(inner, std::min(340.0f, float(std::max<size_t>(shown.size(), 1)) * (ImGui::GetTextLineHeightWithSpacing() + 2) + 8)));
        if (shown.empty()) small_dim("No activity yet");
        for (auto& l : shown) {
            int lv = log_level(l);
            ImGui::TextColored(lv == 1 ? P.red : lv == 2 ? P.orange : P.dim, "%s",
                               lv == 1 ? ICON_FA_CIRCLE_EXCLAMATION : lv == 2 ? ICON_FA_TRIANGLE_EXCLAMATION : ICON_FA_CIRCLE_INFO);
            ImGui::SameLine(0, 8);
            ImGui::PushTextWrapPos(0);
            ImGui::TextUnformatted(l.c_str());
            ImGui::PopTextWrapPos();
        }
        ImGui::EndChild();
    }
    // click outside closes it (but not the click that opened it)
    if (ImGui::IsMouseClicked(0) && !ImGui::IsWindowHovered(ImGuiHoveredFlags_ChildWindows | ImGuiHoveredFlags_AllowWhenBlockedByActiveItem)) {
        ImGuiWindow* hov = ImGui::GetCurrentContext()->HoveredWindow;
        if (!hov || strcmp(hov->Name, "##cluster") != 0) g_status_open = false;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Escape)) g_status_open = false;
    ImGui::End();
}

// ---------------------------------------------------------------------------------------------------
// Help

namespace {

struct Concept {
    const char* icon;
    const char* name;
    const char* line;
    const char* where;
};
const Concept kConcepts[] = {
    {ICON_FA_VAULT, "Vault", "Your files on S3-compatible storage, in one folder of a bucket, readable only by s3vault with your password.",
     "Sidebar › All Files"},
    {ICON_FA_FOLDER, "Synced folder", "A folder on this computer kept in sync with a folder in the vault, in the background.",
     "Sidebar › Synced folders"},
    {ICON_FA_KEY, "Encryption and the key", "Each file is encrypted on this computer with a random key; your password protects that key.",
     "Settings › Security"},
    {ICON_FA_CODE_MERGE, "Conflicts", "When the same file changes on two devices, nothing is overwritten: you choose what to keep.",
     "Sidebar › Conflicts"},
    {ICON_FA_TRASH, "Trash", "Deleted files go to the vault trash first, so you can put them back.", "Sidebar › Trash"},
    {ICON_FA_LOCK, "Lock", "Locking hides the window; syncing keeps running behind it.", "Sidebar › lock button"},
};

struct Term {
    const char* term;
    const char* def;
};
const Term kGlossary[] = {
    {"Bucket", "A storage container at your provider (Cloudflare R2, AWS S3, MinIO…). The vault lives inside one."},
    {"Conflict", "A file changed on two devices before they synced. s3vault keeps both until you decide."},
    {"Direction", "How a synced folder syncs: both ways, back up only (upload), or mirror only (download)."},
    {"Keychain", "The system's password store. s3vault keeps the storage secret there, never in a file."},
    {"Key file", "key.gpg in the vault: the vault key, encrypted with your password."},
    {"Lock", "Hides the window until you unlock it; syncing keeps running."},
    {"Recovery key", "The raw vault key. With it and the key file, the vault opens even if the password is lost."},
    {"Synced folder", "A folder on this computer kept in sync with a folder in the vault."},
    {"Transfer", "One upload or download. Running transfers show in Tasks."},
    {"Vault", "Your encrypted files on storage you own, in one folder of a bucket."},
    {"Vault folder", "The folder inside the bucket that holds the vault. Several vaults can share one bucket."},
    {"Vault password", "Protects the key that encrypts your files. It cannot be recovered if lost."},
    {"Vault trash", "Where deleted files wait before they are removed for good."},
};

bool match(const char* a, const std::string& q) {
    if (q.empty()) return true;
    return to_lower(tr(a)).find(q) != std::string::npos || to_lower(a).find(q) != std::string::npos;
}

}  // namespace

std::vector<std::pair<const char*, const char*>> help_topics() {
    std::vector<std::pair<const char*, const char*>> r;
    for (auto& t : kGlossary) r.push_back({t.term, t.def});
    return r;
}

void draw_help(App& a) {
    if (!g_help_open) return;
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowSize(ImVec2(std::min(680.0f, vp->Size.x - 60), std::min(560.0f, vp->Size.y - 60)), ImGuiCond_Appearing);
    ImGui::SetNextWindowPos(vp->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, P.card);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 12);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 14));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1);
    bool open = ImGui::Begin("##help", &g_help_open, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoCollapse);
    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor();
    if (!open) { ImGui::End(); return; }
    // Keep at least the header inside the app window.
    ImVec2 wp = ImGui::GetWindowPos(), ws = ImGui::GetWindowSize();
    ImVec2 np(std::clamp(wp.x, vp->Pos.x - ws.x + 120, vp->Pos.x + vp->Size.x - 120), std::clamp(wp.y, vp->Pos.y, vp->Pos.y + vp->Size.y - 48));
    if (np.x != wp.x || np.y != wp.y) ImGui::SetWindowPos(np);

    ImGui::TextColored(P.accent, ICON_FA_CIRCLE_QUESTION);
    ImGui::SameLine(0, 8);
    title_text("Help", 1.15f);
    ImGui::SameLine(ImGui::GetWindowContentRegionMax().x - 30);
    if (icon_button(ICON_FA_XMARK, "Close  (Esc)", false, true, 28)) g_help_open = false;
    if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    search_field("##helpq", g_help_q, sizeof g_help_q, ImGui::GetContentRegionAvail().x - prefs::seg_width({"Concepts", "Glossary", "Shortcuts"}) - 10,
                 "Search help");
    ImGui::SameLine();
    prefs::seg("##helptab", &g_help_tab, {"Concepts", "Glossary", "Shortcuts"});
    ImGui::Dummy(ImVec2(0, 6));
    std::string q = to_lower(trim(g_help_q));

    ImGui::BeginChild("##helpbody", ImVec2(0, 0));
    float wrap = ImGui::GetContentRegionAvail().x - 8;
    if (g_help_tab == 0) {
        for (auto& c : kConcepts) {
            if (!match(c.name, q) && !match(c.line, q)) continue;
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImGui::BeginGroup();
            ImGui::Dummy(ImVec2(0, 6));
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 12);
            ImGui::TextColored(P.accent, "%s", c.icon);
            ImGui::SameLine(0, 10);
            ImGui::BeginGroup();
            ImGui::TextUnformatted(tr(c.name));
            ImGui::PushStyleColor(ImGuiCol_Text, P.dim);
            ImGui::PushTextWrapPos(p.x - ImGui::GetWindowPos().x + wrap - 12);
            ImGui::TextWrapped("%s", tr(c.line));
            ImGui::PopTextWrapPos();
            ImGui::PopStyleColor();
            small_dim("%s", trf("Where you see it: %s", tr(c.where)).c_str());
            ImGui::EndGroup();
            ImGui::Dummy(ImVec2(0, 6));
            ImGui::EndGroup();
            ImVec2 e = ImGui::GetItemRectMax();
            ImGui::GetWindowDrawList()->AddRect(p, ImVec2(p.x + wrap, e.y), col(P.border), 10);
            ImGui::Dummy(ImVec2(0, 4));
        }
    } else if (g_help_tab == 1) {
        // A–Z in the current language
        std::vector<const Term*> terms;
        for (auto& t : kGlossary) terms.push_back(&t);
        std::sort(terms.begin(), terms.end(), [](const Term* x, const Term* y) { return strcmp(tr(x->term), tr(y->term)) < 0; });
        for (const Term* tp : terms) {
            const Term& t = *tp;
            if (!match(t.term, q) && !match(t.def, q)) continue;
            bool focus = g_help_focus == t.term;
            if (focus) { ImGui::SetScrollHereY(0.2f); g_help_focus.clear(); }
            ImGui::TextUnformatted(tr(t.term));
            ImGui::PushStyleColor(ImGuiCol_Text, P.dim);
            ImGui::PushTextWrapPos(wrap);
            ImGui::TextWrapped("%s", tr(t.def));
            ImGui::PopTextWrapPos();
            ImGui::PopStyleColor();
            ImGui::Dummy(ImVec2(0, 6));
        }
    } else {
        const char* groups[] = {"General", "Navigation", "Files", "Editor", "View"};
        for (const char* g : groups) {
            bool any = false;
            for (auto& s : shortcuts()) any |= !strcmp(s.group, g) && (match(s.action, q) || to_lower(s.keys).find(q) != std::string::npos);
            if (!any) continue;
            ImGui::Dummy(ImVec2(0, 4));
            std::string gu = tr(g);
            small_dim("%s", gu.c_str());
            for (auto& s : shortcuts()) {
                if (strcmp(s.group, g) || !(match(s.action, q) || to_lower(s.keys).find(q) != std::string::npos)) continue;
                ImGui::TextUnformatted(tr(s.action));
                ImGui::SameLine(wrap * 0.62f);
                key_chips(s.keys);
            }
        }
        ImGui::Dummy(ImVec2(0, 8));
        if (button(ICON_FA_COPY "  Copy all", Btn::Secondary)) {
            std::string all;
            for (auto& s : shortcuts()) all += std::string(s.keys) + "\t" + tr(s.action) + "\n";
            glfwSetClipboardString(a.win, all.c_str());
            a.notify(tr("Copied"));
        }
    }
    ImGui::EndChild();
    if (ImGui::IsKeyPressed(ImGuiKey_Escape) && ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows)) g_help_open = false;
    ImGui::End();
}

}  // namespace s3v::ui
