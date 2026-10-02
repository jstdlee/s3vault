// Conflicts, Transfers and Trash.
#include <GLFW/glfw3.h>

#include <algorithm>
#include <map>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "imgui.h"
#include "util/fs.h"
#include "util/strings.h"

namespace s3v::ui {

// A scrolling page under the header, on the window background, with centred cards.
static void body_begin(float top) {
    ImGui::SetCursorPos(ImVec2(0, top));
    ImGui::BeginChild("##body", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_None);
    prefs::page_begin(820);
}
static void body_end() {
    prefs::page_end();
    ImGui::EndChild();
}

static bool checkbox_round(const char* id, bool v) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    float s = ImGui::GetTextLineHeight() + 2;
    ImGui::PushID(id);
    bool clicked = ImGui::InvisibleButton("##cb", ImVec2(s, s));
    ImGui::PopID();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 c(p.x + s / 2, p.y + s / 2);
    if (v) {
        dl->AddCircleFilled(c, s / 2 - 1, col(P.accent), 20);
        ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 0.7f);
        ImVec2 ts = ImGui::CalcTextSize(ICON_FA_CHECK);
        dl->AddText(ImVec2(c.x - ts.x / 2, c.y - ts.y / 2), col(P.on_accent), ICON_FA_CHECK);
        ImGui::PopFont();
    } else {
        dl->AddCircle(c, s / 2 - 1, col(P.faint), 20, 1.5f);
    }
    return clicked;
}

// ---------------------------------------------------------------------------------------------------
// Conflicts

static const char* what_happened(const std::string& kind) {
    if (kind == "both-modified") return "Changed on this device and on another";
    if (kind == "both-added") return "Added on two devices with different contents";
    if (kind == "remote-deleted") return "Changed here, deleted on another device";
    if (kind == "local-deleted") return "Deleted here, changed on another device";
    return kind.c_str();
}

void draw_conflicts_view(App& a) {
    auto list = a.db.conflicts();
    auto roots = a.db.roots();
    std::set<int64_t> live;
    for (auto& c : list) live.insert(c.id);
    for (auto it = a.conflict_sel.begin(); it != a.conflict_sel.end();) it = live.count(*it) ? std::next(it) : a.conflict_sel.erase(it);

    float top = page_header("Conflicts", list.empty() ? nullptr : "Nothing is overwritten until you choose");
    if (list.empty()) {
        ImGui::SetCursorPos(ImVec2(0, top));
        ImGui::BeginChild("##empty");
        empty_state(ICON_FA_CIRCLE_CHECK, "No Conflicts", "When a file changes on two devices at once, it waits here for you.");
        ImGui::EndChild();
        return;
    }
    float bar_h = 58;
    float W = ImGui::GetWindowWidth(), H = ImGui::GetWindowHeight();
    ImGui::SetCursorPos(ImVec2(0, top));
    ImGui::BeginChild("##body", ImVec2(0, H - top - bar_h));
    prefs::page_begin(860);

    std::map<std::string, std::vector<const ConflictRow*>> groups;  // "~/Documents/notes" → rows
    for (auto& c : list) {
        std::string rp = "?";
        for (auto& r : roots)
            if (r.id == c.root_id) rp = display_path(r.local_path);
        std::string d = path_dirname(c.rel);
        groups[d.empty() ? rp : rp + "/" + d].push_back(&c);
    }
    for (auto& [title, items] : groups) {
        prefs::section(title.c_str(), false);
        prefs::card_begin();
        for (auto* c : items) {
            bool on = a.conflict_sel.count(c->id) > 0;
            std::string name = path_basename(c->rel);
            std::string desc = std::string(what_happened(c->kind)) + "  ·  here: " +
                               (c->local_exists ? human_size(c->local_size) + ", " + format_local_time(c->local_mtime) : "deleted") +
                               "  ·  server: " +
                               (c->remote_exists ? human_size(c->remote_size) + ", " + format_local_time(c->remote_mtime) : "deleted");
            float cw = ImGui::CalcTextSize("Compare").x + 28;
            ImVec2 row_top = ImGui::GetCursorScreenPos();
            std::string title_row = std::string("        ") + type_icon(name, false) + "  " + name;  // room for the checkbox
            prefs::row(title_row.c_str(), desc.c_str(), cw, [&] {
                if (button("Compare", Btn::Secondary, ImVec2(cw, 0))) {
                    a.modal_arg = std::to_string(c->id);
                    a.modal = "compare";
                }
            });
            ImVec2 after = ImGui::GetCursorScreenPos();
            // Checkbox + type icon, drawn in the space left at the start of the title line.
            ImGui::SetCursorScreenPos(ImVec2(row_top.x + 14, row_top.y + 13));
            ImGui::PushID(int(c->id));
            if (checkbox_round("sel", on)) {
                if (on) a.conflict_sel.erase(c->id);
                else a.conflict_sel.insert(c->id);
            }
            ImGui::PopID();
            ImGui::SetCursorScreenPos(after);
        }
        prefs::card_end();
    }
    prefs::page_end();
    ImGui::EndChild();

    // Action bar
    ImGui::SetCursorPos(ImVec2(0, H - bar_h));
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::GetWindowDrawList()->AddLine(p, ImVec2(p.x + W, p.y), col(P.divider));
    ImGui::SetCursorPos(ImVec2(16, H - bar_h + (bar_h - ImGui::GetFrameHeight()) / 2));
    size_t nsel = a.conflict_sel.size();
    if (button(nsel == list.size() ? "Select None" : "Select All", Btn::Plain)) {
        if (nsel == list.size()) a.conflict_sel.clear();
        else for (auto& c : list) a.conflict_sel.insert(c.id);
    }
    ImGui::SameLine();
    ImGui::AlignTextToFramePadding();
    small_dim("%zu of %zu selected", nsel, list.size());
    struct Act { const char* label; const char* id; const char* tip; };
    Act acts[] = {{"Keep Both", "keep-both", "Your version keeps the name; the server's is saved next to it"},
                  {"Use This Device's", "keep-local", "Your version replaces the one on the server"},
                  {"Use Server's", "keep-remote", "The server's version replaces yours (yours goes to the desktop trash)"},
                  {"Use Newest", "keep-newest", "Keep whichever side changed last"}};
    float x = W - 20;
    for (auto& ac : acts) {
        float bw = ImGui::CalcTextSize(ac.label).x + 28;
        x -= bw;
        ImGui::SetCursorPos(ImVec2(x, H - bar_h + (bar_h - ImGui::GetFrameHeight()) / 2));
        bool primary = std::string(ac.id) == "keep-both";
        if (button(ac.label, primary ? Btn::Primary : Btn::Secondary, ImVec2(bw, 0), nsel > 0 && a.busy == 0)) {
            a.modal_arg = ac.id;
            a.modal = "resolve";
        }
        tip(ac.tip);
        x -= 8;
    }
}

// ---------------------------------------------------------------------------------------------------
// Transfers

void draw_transfers_view(App& a) {
    auto ts = a.engine ? a.engine->transfers() : std::vector<Transfer>{};
    size_t queued = 0;
    for (auto& t : ts) queued += t.queued;
    std::string sub = ts.empty() ? "" : std::to_string(ts.size() - queued) + " in progress · " + std::to_string(queued) + " waiting";
    float top = page_header("Transfers", sub.c_str());
    body_begin(top);
    prefs::section("Now");
    prefs::card_begin();
    if (ts.empty()) prefs::info("Nothing is transferring", "Uploads, downloads and sync work show up here", "");
    int shown = 0;
    for (int pass = 0; pass < 2; pass++) {
        for (auto& t : ts) {
            if (t.queued != (pass == 1)) continue;
            if (++shown > 200) break;
            std::string name = path_basename(t.path);
            std::string desc = (t.what == "upload" ? "Uploading to /" : t.what == "download" ? "Downloading /" : "Comparing /") + t.path;
            float pw = 220;
            prefs::row(name.c_str(), desc.c_str(), pw, [&] {
                if (t.queued) {
                    ImGui::AlignTextToFramePadding();
                    small_dim("Waiting · %s", human_size(t.total).c_str());
                } else {
                    float f = t.total ? float(double(t.done) / double(t.total)) : 0.0f;
                    ImGui::BeginGroup();
                    progress(f, pw, 5);
                    if (t.total && t.done >= t.total) small_dim("Finishing…");  // bytes sent; waiting for the server to confirm
                    else small_dim("%s of %s", human_size(t.done).c_str(), human_size(t.total).c_str());
                    ImGui::EndGroup();
                }
            });
        }
    }
    prefs::card_end();

    prefs::section("Activity");
    prefs::card_begin();
    auto lines = a.engine ? a.engine->log_lines(300) : std::vector<std::string>{};
    if (lines.empty()) prefs::info("No activity yet", "Everything s3vault does is listed here", "");
    for (auto it = lines.rbegin(); it != lines.rend(); ++it) {  // newest first
        const std::string& l = *it;
        std::string when = l.size() > 10 ? l.substr(0, 8) : "";
        std::string what = l.size() > 10 ? l.substr(10) : l;
        bool bad = what.find("failed") != std::string::npos || what.find("error") != std::string::npos;
        std::string icon = bad ? ICON_FA_CIRCLE_EXCLAMATION
                         : what.rfind("uploaded", 0) == 0 ? ICON_FA_CLOUD_ARROW_UP
                         : what.rfind("downloaded", 0) == 0 ? ICON_FA_CLOUD_ARROW_DOWN
                         : what.rfind("deleted", 0) == 0 ? ICON_FA_TRASH
                         : what.rfind("sync", 0) == 0 ? ICON_FA_ARROWS_ROTATE : ICON_FA_CIRCLE_INFO;
        std::string row_title = icon + "   " + what;
        prefs::row(row_title.c_str(), nullptr, ImGui::CalcTextSize(when.c_str()).x, [&] {
            ImGui::AlignTextToFramePadding();
            ImGui::TextDisabled("%s", when.c_str());
        });
    }
    prefs::card_end();
    body_end();
}

// ---------------------------------------------------------------------------------------------------
// Trash

void draw_trash_view(App& a) {
    if (a.trash_dirty && !a.trash_loading && a.vault && a.conn == App::Conn::Ready) {
        a.trash_dirty = false;
        a.trash_loading = true;
        auto v = a.vault;
        a.run_job([&a, v] {
            OpResult err;
            auto list = v->trash_list(&err);
            a.post([&a, list, err] {
                a.trash_loading = false;
                a.trash = list;
                if (!err.ok && !err.error.empty()) a.notify(err.error, true);
            });
        });
    }
    std::string sub = a.trash.empty() ? "" : std::to_string(a.trash.size()) + " items · kept " + std::to_string(a.cfg.sync.trash_days) + " days";
    float top = page_header("Trash", sub.c_str());
    float W = ImGui::GetWindowWidth();
    ImGui::SetCursorPos(ImVec2(W - 20 - 130, (52 - ImGui::GetFrameHeight()) / 2));
    if (button("Empty Trash…", Btn::Destructive, ImVec2(130, 0), !a.trash.empty())) a.modal = "empty-trash";
    if (!a.trash_sel.empty()) {
        ImGui::SetCursorPos(ImVec2(W - 20 - 130 - 8 - 120, (52 - ImGui::GetFrameHeight()) / 2));
        if (button("Put Back", Btn::Primary, ImVec2(120, 0))) {
            std::vector<TrashEntry> todo;
            for (auto& t : a.trash)
                if (a.trash_sel.count(t.key)) todo.push_back(t);
            auto v = a.vault;
            auto eng = a.engine;
            a.run_job([&a, v, eng, todo] {
                int ok = 0;
                for (auto& t : todo) {
                    OpResult r = v->restore(t);
                    if (r.ok) ok++;
                    if (eng) eng->log(r.ok ? "restored /" + t.logical : "restore failed: /" + t.logical + " (" + r.error + ")");
                }
                a.post([&a, ok] {
                    a.trash_sel.clear();
                    a.trash_dirty = true;
                    a.tree_dirty = true;
                    a.notify("Put back " + plural(ok, "item"));
                    if (a.engine) a.engine->request_sync();
                });
            });
        }
    }
    ImGui::SetCursorPos(ImVec2(0, top));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, P.card);
    ImGui::BeginChild("##trash");
    ImGui::PopStyleColor();
    if (a.trash_loading && a.trash.empty()) {
        empty_state(ICON_FA_TRASH, "Loading…", "");
    } else if (a.trash.empty()) {
        empty_state(ICON_FA_TRASH, "Trash Is Empty", "Deleted files stay here for a while so you can put them back.");
    } else if (ImGui::BeginTable("##t", 4, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_PadOuterX)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Original Location", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Date Deleted", ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableNextRow(ImGuiTableRowFlags_Headers);
        for (int c = 0; c < 4; c++) {
            ImGui::TableSetColumnIndex(c);
            ImGui::PushStyleColor(ImGuiCol_Text, P.dim);
            ImGui::TableHeader(ImGui::TableGetColumnName(c));
            ImGui::PopStyleColor();
        }
        for (auto& t : a.trash) {
            ImGui::TableNextRow(0, ImGui::GetFrameHeight() + 2);
            ImGui::TableNextColumn();
            bool sel = a.trash_sel.count(t.key) > 0;
            ImGui::PushID(t.key.c_str());
            ImGui::PushStyleColor(ImGuiCol_HeaderHovered, P.hover);
            ImGui::AlignTextToFramePadding();
            if (ImGui::Selectable("##r", sel, ImGuiSelectableFlags_SpanAllColumns, ImVec2(0, ImGui::GetFrameHeight()))) {
                if (!ImGui::GetIO().KeyCtrl) a.trash_sel.clear();
                if (sel && ImGui::GetIO().KeyCtrl) a.trash_sel.erase(t.key);
                else a.trash_sel.insert(t.key);
            }
            ImGui::PopStyleColor();
            ImGui::SameLine(0, 4);
            std::string name = path_basename(t.logical);
            ImGui::TextColored(type_color(name, false), "%s", type_icon(name, false));
            ImGui::SameLine(0, 8);
            ImGui::TextUnformatted(name.c_str());
            if (t.encrypted) { ImGui::SameLine(0, 6); ImGui::TextColored(P.faint, ICON_FA_LOCK); }
            ImGui::TableNextColumn();
            ImGui::AlignTextToFramePadding();
            ImGui::TextDisabled("/%s", path_dirname(t.logical).c_str());
            ImGui::TableNextColumn();
            ImGui::AlignTextToFramePadding();
            ImGui::TextDisabled("%s", format_local_time(t.deleted_at).c_str());
            ImGui::TableNextColumn();
            ImGui::AlignTextToFramePadding();
            ImGui::TextDisabled("%s", human_size(t.size).c_str());
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
}

}  // namespace s3v::ui
