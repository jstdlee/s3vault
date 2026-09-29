// Built-in file/folder picker. External dialogs (zenity/kdialog) have no transient parent, so GNOME
// opens them behind the s3vault window; an in-window browser avoids that and works the same everywhere.
#include <dirent.h>
#include <sys/stat.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <map>
#include <set>

#include <GLFW/glfw3.h>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "imgui.h"
#include "util/fs.h"
#include "util/strings.h"

namespace s3v::ui {

namespace {

struct Item {
    std::string name;
    bool dir = false;
    uint64_t size = 0;
    int64_t mtime = 0;
};

struct Browser {
    bool want_open = false;
    BrowseMode mode = BrowseMode::OpenMany;
    std::string title;
    std::string cwd;
    std::vector<Item> items;
    std::set<std::string> sel;
    int anchor = -1;  // for shift-click ranges
    bool show_hidden = false;
    char path_buf[2048] = "";
    char name_buf[512] = "";
    std::string error;
    std::string confirm_overwrite;
    std::function<void(std::vector<std::string>)> on_ok;
    std::map<int, std::string> last_dir;  // per mode
};

Browser& B() {
    static Browser b;
    return b;
}

std::string join(const std::string& dir, const std::string& name) { return dir == "/" ? "/" + name : dir + "/" + name; }

void list(Browser& b) {
    b.items.clear();
    b.sel.clear();
    b.anchor = -1;
    b.error.clear();
    b.confirm_overwrite.clear();
    DIR* d = opendir(b.cwd.c_str());
    if (!d) {
        b.error = std::string("cannot open folder: ") + strerror(errno);
    } else {
        while (dirent* e = readdir(d)) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            if (!b.show_hidden && e->d_name[0] == '.') continue;
            FileStat st = stat_path(join(b.cwd, e->d_name), true);  // follow links: a link to a folder is a folder
            if (!st.exists) continue;
            b.items.push_back({e->d_name, st.is_dir, st.size, st.mtime_ns / 1000000000LL});
        }
        closedir(d);
    }
    std::sort(b.items.begin(), b.items.end(), [](const Item& x, const Item& y) {
        if (x.dir != y.dir) return x.dir;
        return strcasecmp(x.name.c_str(), y.name.c_str()) < 0;
    });
    snprintf(b.path_buf, sizeof b.path_buf, "%s", b.cwd.c_str());
}

void go(Browser& b, std::string dir) {
    while (dir.size() > 1 && dir.back() == '/') dir.pop_back();
    if (dir.empty()) dir = "/";
    if (!stat_path(dir, true).is_dir) {
        b.error = "not a folder: " + dir;
        return;
    }
    b.cwd = dir;
    b.last_dir[int(b.mode)] = dir;
    list(b);
}

void accept(Browser& b, std::vector<std::string> paths) {
    if (paths.empty()) return;
    auto cb = std::move(b.on_ok);
    b.on_ok = nullptr;
    ImGui::CloseCurrentPopup();
    if (cb) cb(std::move(paths));
}

}  // namespace

void browse(App& a, BrowseMode mode, const std::string& title, std::function<void(std::vector<std::string>)> on_ok,
            const std::string& suggested_name) {
    (void)a;
    Browser& b = B();
    b.mode = mode;
    b.title = title;
    b.on_ok = std::move(on_ok);
    snprintf(b.name_buf, sizeof b.name_buf, "%s", suggested_name.c_str());
    auto it = b.last_dir.find(int(mode));
    std::string start = it != b.last_dir.end() && stat_path(it->second, true).is_dir ? it->second : home_dir();
    b.cwd = start;
    list(b);
    b.want_open = true;
}

void draw_file_browser(App& a) {
    Browser& b = B();
    const char* id = "###filebrowser";
    if (b.want_open) {
        ImGui::OpenPopup(id);
        b.want_open = false;
    }
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(std::min(900.0f, vp->WorkSize.x - 40), std::min(560.0f, vp->WorkSize.y - 40)), ImGuiCond_Appearing);
    std::string title = b.title + id;
    bool open = true;
    if (!ImGui::BeginPopupModal(title.c_str(), &open)) return;
    if (!open) {
        b.on_ok = nullptr;
        ImGui::EndPopup();
        return;
    }

    // Toolbar: up, home, editable path, hidden files.
    if (ImGui::Button(ICON_FA_ARROW_UP)) go(b, path_dirname(b.cwd).empty() ? "/" : path_dirname(b.cwd));
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Parent folder (Backspace)");
    ImGui::SameLine();
    if (ImGui::Button(ICON_FA_HOUSE)) go(b, home_dir());
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-160);
    if (ImGui::InputText("##path", b.path_buf, sizeof b.path_buf, ImGuiInputTextFlags_EnterReturnsTrue)) {
        std::string p = trim(b.path_buf);
        if (starts_with(p, "~")) p = home_dir() + p.substr(1);
        FileStat st = stat_path(p, true);
        if (st.is_dir) go(b, p);
        else if (st.is_file && b.mode == BrowseMode::OpenMany) accept(b, {p});
        else if (b.mode == BrowseMode::Save && stat_path(path_dirname(p), true).is_dir) {
            snprintf(b.name_buf, sizeof b.name_buf, "%s", path_basename(p).c_str());
            go(b, path_dirname(p));
        } else b.error = "not found: " + p;
    }
    ImGui::SameLine();
    if (ImGui::Checkbox("Hidden", &b.show_hidden)) list(b);

    float footer = ImGui::GetFrameHeightWithSpacing() * (b.mode == BrowseMode::Save ? 2.3f : 1.3f) + (b.error.empty() ? 0 : ImGui::GetTextLineHeightWithSpacing());
    // Places
    ImGui::BeginChild("places", ImVec2(170, -footer), ImGuiChildFlags_Borders);
    auto place = [&](const char* icon, const std::string& label, const std::string& path) {
        if (!stat_path(path, true).is_dir) return;
        if (ImGui::Selectable((std::string(icon) + "  " + label + "##" + path).c_str(), b.cwd == path)) go(b, path);
    };
    std::string h = home_dir();
    place(ICON_FA_HOUSE, "Home", h);
    place(ICON_FA_DESKTOP, "Desktop", h + "/Desktop");
    place(ICON_FA_FILE_LINES, "Documents", h + "/Documents");
    place(ICON_FA_DOWNLOAD, "Downloads", h + "/Downloads");
    place(ICON_FA_FILE_IMAGE, "Pictures", h + "/Pictures");
    place(ICON_FA_HARD_DRIVE, "Computer", "/");
    // Mounted drives
    const char* user = getenv("USER");
    for (std::string base : {std::string("/media/") + (user ? user : ""), std::string("/run/media/") + (user ? user : ""), std::string("/mnt")}) {
        if (DIR* d = opendir(base.c_str())) {
            while (dirent* e = readdir(d))
                if (e->d_name[0] != '.') place(ICON_FA_HARD_DRIVE, e->d_name, base + "/" + e->d_name);
            closedir(d);
        }
    }
    ImGui::EndChild();
    ImGui::SameLine();

    // Folder listing
    std::string nav_to;
    std::vector<std::string> accept_now;
    if (ImGui::BeginTable("items", 3, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable,
                          ImVec2(0, -footer))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90);
        ImGui::TableSetupColumn("Modified", ImGuiTableColumnFlags_WidthFixed, 130);
        ImGui::TableHeadersRow();
        ImGuiListClipper clip;
        clip.Begin(int(b.items.size()));
        while (clip.Step()) {
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
                const Item& it = b.items[size_t(i)];
                bool files_disabled = b.mode == BrowseMode::Folder && !it.dir;
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(i);
                ImGui::BeginDisabled(files_disabled);
                bool selected = b.sel.count(it.name) > 0;
                std::string label = std::string(type_icon(it.name, it.dir, false)) + "  " + it.name;
                if (ImGui::Selectable(label.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    ImGuiIO& io = ImGui::GetIO();
                    if (io.KeyShift && b.anchor >= 0 && b.mode == BrowseMode::OpenMany) {
                        b.sel.clear();
                        for (int k = std::min(b.anchor, i); k <= std::max(b.anchor, i); k++) b.sel.insert(b.items[size_t(k)].name);
                    } else if (io.KeyCtrl && b.mode == BrowseMode::OpenMany) {
                        if (!b.sel.erase(it.name)) b.sel.insert(it.name);
                        b.anchor = i;
                    } else {
                        b.sel = {it.name};
                        b.anchor = i;
                        if (b.mode == BrowseMode::Save && !it.dir) snprintf(b.name_buf, sizeof b.name_buf, "%s", it.name.c_str());
                    }
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                        if (it.dir) nav_to = join(b.cwd, it.name);
                        else if (b.mode == BrowseMode::OpenMany) accept_now = {join(b.cwd, it.name)};
                        else if (b.mode == BrowseMode::Save) accept_now = {join(b.cwd, it.name)};
                    }
                }
                ImGui::EndDisabled();
                ImGui::TableNextColumn();
                if (!it.dir) ImGui::TextDisabled("%s", human_size(it.size).c_str());
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", format_local_time(it.mtime).c_str());
                ImGui::PopID();
            }
        }
        if (b.items.empty() && b.error.empty()) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("(empty folder)");
        }
        ImGui::EndTable();
    }
    if (!ImGui::IsAnyItemActive() && ImGui::IsKeyPressed(ImGuiKey_Backspace)) nav_to = path_dirname(b.cwd).empty() ? "/" : path_dirname(b.cwd);

    if (!b.error.empty()) ImGui::TextColored(ImVec4(1, 0.45f, 0.4f, 1), "%s", b.error.c_str());

    // Footer
    bool enter = !ImGui::IsAnyItemActive() && (ImGui::IsKeyPressed(ImGuiKey_Enter) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter));
    if (b.mode == BrowseMode::Save) {
        ImGui::SetNextItemWidth(-1);
        if (ImGui::InputTextWithHint("##name", "File name", b.name_buf, sizeof b.name_buf, ImGuiInputTextFlags_EnterReturnsTrue)) enter = true;
    }
    std::string ok_label;
    std::vector<std::string> result;
    switch (b.mode) {
        case BrowseMode::OpenMany: {
            for (auto& n : b.sel) result.push_back(join(b.cwd, n));
            ok_label = result.empty() ? "Select files or folders" : "Choose " + std::to_string(result.size()) + " item(s)";
            ImGui::TextDisabled("Ctrl/Shift-click to select several; folders are uploaded with their contents.");
            break;
        }
        case BrowseMode::Folder: {
            std::string target = b.sel.empty() ? b.cwd : join(b.cwd, *b.sel.begin());
            result = {target};
            ok_label = "Choose \"" + path_basename(target) + "\"";
            if (target == "/") ok_label = "Choose /";
            ImGui::TextDisabled("Select a folder, or open it and choose it from inside.");
            break;
        }
        case BrowseMode::Save: {
            std::string name = trim(b.name_buf);
            if (!name.empty()) result = {join(b.cwd, name)};
            ok_label = "Save here";
            if (!b.confirm_overwrite.empty()) ImGui::TextColored(ImVec4(1, 0.75f, 0.3f, 1), "%s exists; press Save again to replace it.",
                                                                  path_basename(b.confirm_overwrite).c_str());
            break;
        }
    }
    ImGui::SameLine(ImGui::GetContentRegionMax().x - 330);
    ImGui::BeginDisabled(result.empty());
    bool ok = ImGui::Button(ok_label.c_str(), ImVec2(210, 0)) || (enter && !result.empty());
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(100, 0)) || ImGui::IsKeyPressed(ImGuiKey_Escape)) {
        b.on_ok = nullptr;
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return;
    }
    if (ok && b.mode == BrowseMode::Save && !result.empty()) {
        if (stat_path(result[0], true).is_dir) { nav_to = result[0]; ok = false; }
        else if (stat_path(result[0], true).exists && b.confirm_overwrite != result[0]) { b.confirm_overwrite = result[0]; ok = false; }
    }
    if (!accept_now.empty()) {
        if (b.mode == BrowseMode::Save && stat_path(accept_now[0], true).exists && b.confirm_overwrite != accept_now[0])
            b.confirm_overwrite = accept_now[0];
        else accept(b, accept_now);
    } else if (ok) {
        accept(b, result);
    } else if (!nav_to.empty()) {
        go(b, nav_to);
    }
    ImGui::EndPopup();
}

}  // namespace s3v::ui
