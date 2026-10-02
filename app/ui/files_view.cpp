// Files: Finder-style list of the current folder (disclosure triangles, folders first), a toolbar with
// history + breadcrumb + search, and an inspector with Quick Look preview, info and actions.
#include <GLFW/glfw3.h>

#include <algorithm>
#include <cstring>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "imgui.h"
#include "imgui_internal.h"
#include "util/fs.h"
#include "util/strings.h"

namespace s3v::ui {

static std::vector<std::string> g_visible;  // rows in display order (for arrow keys / select all)

static const Node* current_folder(App& a) {
    if (!a.tree) return nullptr;
    if (a.cwd.empty()) return a.tree.get();
    const Node* n = find_node(a.tree.get(), a.cwd);
    return n && n->dir ? n : nullptr;
}

static std::string folder_title(const std::string& logical) { return logical.empty() ? std::string(tr("All Files")) : path_basename(logical); }

static void select_only(App& a, const std::string& path) {
    if (a.selected != path && a.preview.state != PreviewState::Empty) preview_free(a);
    a.multi.clear();
    a.selected = path;
}

static void begin_rename(App& a, const std::string& path) {
    snprintf(a.text_buf, sizeof a.text_buf, "%s", path_basename(path).c_str());
    a.modal_arg = path;
    a.modal = "rename";
}

static void begin_delete(App& a) {
    if (!a.multi.empty()) a.modal = "delete-multi";
    else if (!a.selected.empty()) { a.modal_arg = a.selected; a.modal = "delete"; }
}

static void quick_look(App& a, const Node& n) {
    if (n.dir) return;
    if (preview_kind(n.logical) == PreviewKind::None) {
        a.notify(tr("No preview for this kind of file — use Download"), true);
        return;
    }
    a.cfg.ui.inspector = 1;
    if (a.preview.state != PreviewState::Empty && a.preview.logical == n.logical) preview_free(a);  // Space toggles
    else preview_load(a, n.entry);
}

static void context_menu(App& a, const Node& n) {
    if (!ImGui::BeginPopupContextItem()) return;
    if (!a.multi.count(n.logical)) select_only(a, n.logical);
    if (n.dir) {
        if (ImGui::MenuItem(tr(ICON_FA_FOLDER_OPEN "   Open"))) navigate(a, n.logical);
    } else {
        if (ImGui::MenuItem(tr(ICON_FA_EYE "   Quick Look"), tr("Space"), false, preview_kind(n.logical) != PreviewKind::None)) quick_look(a, n);
        if (ImGui::MenuItem(tr(ICON_FA_PEN_TO_SQUARE "   Edit"), "Ctrl+E", false, preview_kind(n.logical) == PreviewKind::Text)) open_in_editor(a, n.entry);
        if (ImGui::MenuItem(tr(ICON_FA_DOWNLOAD "   Download…"))) download_to_dialog(a, n.entry);
    }
    ImGui::Separator();
    if (ImGui::MenuItem(tr(ICON_FA_PEN "   Rename…"), "F2")) begin_rename(a, n.logical);
    if (ImGui::MenuItem(tr(ICON_FA_COPY "   Copy Path"))) glfwSetClipboardString(a.win, ("/" + n.logical).c_str());
    ImGui::Separator();
    ImGui::PushStyleColor(ImGuiCol_Text, P.red);
    if (ImGui::MenuItem(tr(ICON_FA_TRASH "   Move to Trash"), "Delete")) begin_delete(a);
    ImGui::PopStyleColor();
    ImGui::EndPopup();
}

// ---------------------------------------------------------------------------------------------------
// toolbar

static void toolbar(App& a) {
    ImGui::SetCursorPos(ImVec2(12, 10));
    if (icon_button(ICON_FA_CHEVRON_LEFT, "Back  (Alt+←)", false, !a.back.empty())) {
        a.fwd.push_back(a.cwd);
        std::string d = a.back.back();
        a.back.pop_back();
        navigate(a, d, false);
    }
    ImGui::SameLine(0, 2);
    if (icon_button(ICON_FA_CHEVRON_RIGHT, "Forward  (Alt+→)", false, !a.fwd.empty())) {
        a.back.push_back(a.cwd);
        std::string d = a.fwd.back();
        a.fwd.pop_back();
        navigate(a, d, false);
    }
    ImGui::SameLine(0, 10);
    // Breadcrumb: All Files › Documents › photos
    std::vector<std::string> parts = a.cwd.empty() ? std::vector<std::string>{} : split(a.cwd, '/');
    // Every crumb and chevron is centred on the toolbar's midline (they differ in size).
    float mid = ImGui::GetCursorPosY() + 15;
    auto crumb = [&](const std::string& label, const std::string& path, bool last) {
        ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * (last ? 1.12f : 1.0f));
        const char* lbl = path.empty() ? tr(label) : label.c_str();  // "All Files" is ours; folder names are not
        ImVec2 ts = ImGui::CalcTextSize(lbl);
        ImGui::SetCursorPosY(mid - ts.y / 2);
        ImVec2 p = ImGui::GetCursorScreenPos();
        ImGui::PushID(path.c_str());
        bool click = ImGui::InvisibleButton("##crumb", ts);
        ImGui::PopID();
        bool hov = ImGui::IsItemHovered() && !last;
        ImGui::GetWindowDrawList()->AddText(p, col(last || hov ? P.text : P.dim), lbl);
        ImGui::PopFont();
        if (!last) tip(trf("Go to %s", label.c_str()));
        if (click && !last) navigate(a, path);
    };
    auto chevron = [&] {
        float sz = ImGui::GetStyle().FontSizeBase * 0.72f;
        ImGui::PushFont(nullptr, sz);
        ImVec2 ts = ImGui::CalcTextSize(ICON_FA_CHEVRON_RIGHT);
        ImGui::PopFont();
        ImVec2 p = ImGui::GetCursorScreenPos();
        float y = ImGui::GetWindowPos().y - ImGui::GetScrollY() + mid - ts.y / 2;
        ImGui::GetWindowDrawList()->AddText(ImGui::GetFont(), sz, ImVec2(p.x, y), col(P.dim, 0.7f), ICON_FA_CHEVRON_RIGHT);
        ImGui::Dummy(ImVec2(ts.x, 1));
    };
    crumb("All Files", "", parts.empty());
    std::string acc;
    for (size_t i = 0; i < parts.size(); i++) {
        acc = acc.empty() ? parts[i] : acc + "/" + parts[i];
        ImGui::SameLine(0, 8);
        chevron();
        ImGui::SameLine(0, 8);
        crumb(parts[i], acc, i + 1 == parts.size());
    }

    // Right side
    float right = ImGui::GetWindowWidth() - 12 - a.chrome_right;
    float icons_w = 4 * 32;
    float search_w = std::clamp(ImGui::GetWindowWidth() * 0.22f, 150.0f, 260.0f);
    ImGui::SetCursorPos(ImVec2(right - icons_w - search_w - 10, 10 + (30 - ImGui::GetFrameHeight()) / 2));
    if (a.focus_search) {
        ImGui::SetKeyboardFocusHere();
        a.focus_search = false;
    }
    if (search_field("##search", a.filter, sizeof a.filter, search_w, "Search vault")) a.tree_dirty = true;
    ImGui::SetCursorPos(ImVec2(right - icons_w, 10));
    if (icon_button(ICON_FA_CLOUD_ARROW_UP, "Upload files or folders  (Ctrl+U)")) choose_and_upload(a);
    ImGui::SameLine(0, 2);
    if (icon_button(ICON_FA_FOLDER_PLUS, "New folder  (Ctrl+Shift+N)")) {
        a.text_buf[0] = 0;
        a.modal = "new-folder";
    }
    ImGui::SameLine(0, 2);
    if (icon_button(ICON_FA_ELLIPSIS, "More")) ImGui::OpenPopup("##more");
    ImGui::SameLine(0, 2);
    if (icon_button(ICON_FA_CIRCLE_INFO, "Show or hide the inspector  (Ctrl+I)", a.cfg.ui.inspector != 0)) {
        a.cfg.ui.inspector = !a.cfg.ui.inspector;
        save_settings(a);
    }
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(6, 6));
    if (ImGui::BeginPopup("##more")) {
        if (ImGui::MenuItem(tr(ICON_FA_ARROWS_ROTATE "   Refresh"), "Ctrl+R")) refresh_listing(a);
        ImGui::Separator();
        if (ImGui::MenuItem(tr(ICON_FA_DOWNLOAD "   Download Everything (Decrypted)…"))) start_download_all(a, true);
        if (ImGui::MenuItem(tr(ICON_FA_LOCK "   Download Everything (As Stored)…"))) start_download_all(a, false);
        ImGui::Separator();
        int tf = a.type_filter;
        const char* types[] = {"All Kinds", "Text & Code", "Images", "PDFs", "Encrypted Files"};
        for (int i = 0; i < 5; i++)
            if (ImGui::MenuItem((std::string("   Show ") + types[i]).c_str(), nullptr, tf == i)) { a.type_filter = i; a.tree_dirty = true; }
        ImGui::EndPopup();
    }
    ImGui::PopStyleVar();
}

// ---------------------------------------------------------------------------------------------------
// list

static void draw_rows(App& a, const Node& n, int depth) {
    for (auto& kp : n.kids) {
        const Node& k = *kp;
        g_visible.push_back(k.logical);
        ImGui::TableNextRow(0, ImGui::GetFrameHeight() + 2);
        ImGui::TableNextColumn();
        ImGui::PushID(k.logical.c_str());
        bool sel = a.selected == k.logical || a.multi.count(k.logical);
        ImGuiTreeNodeFlags f = ImGuiTreeNodeFlags_SpanAllColumns | ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_FramePadding |
                               (sel ? ImGuiTreeNodeFlags_Selected : 0);
        if (!k.dir) f |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
        if (a.filter[0] || a.type_filter) f |= ImGuiTreeNodeFlags_DefaultOpen;
        if (k.dir && a.force_open.erase(k.logical)) ImGui::SetNextItemOpen(true);
        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, P.hover);
        ImGui::PushStyleColor(ImGuiCol_Header, P.select);
        ImGui::PushStyleColor(ImGuiCol_HeaderActive, P.select);
        bool open = ImGui::TreeNodeEx("##n", f);
        ImGui::PopStyleColor(3);
        bool toggled = ImGui::IsItemToggledOpen();
        bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left) && !toggled;
        bool dbl = ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && !toggled;
        context_menu(a, k);
        ImGui::SameLine(0, 2);
        ImGui::TextColored(type_color(k.name, k.dir), "%s", type_icon(k.name, k.dir, open && k.dir));
        ImGui::SameLine(0, 8);
        ImGui::TextUnformatted(k.name.c_str());
        if (!k.dir && k.entry.encrypted) {
            ImGui::SameLine(0, 6);
            ImGui::TextColored(P.faint, ICON_FA_LOCK);
            tip("Encrypted (OpenPGP)");
        }
        if (k.tracked_root) {
            ImGui::SameLine(0, 6);
            ImGui::TextColored(P.green, ICON_FA_ARROWS_ROTATE);
            tip(trf("Kept in sync with %s", k.tracked_info.c_str()));
        }
        if (clicked) {
            ImGuiIO& io = ImGui::GetIO();
            if (io.KeyCtrl) {
                if (!a.selected.empty() && a.multi.empty()) a.multi.insert(a.selected);
                if (!a.multi.erase(k.logical)) a.multi.insert(k.logical);
                a.selected = k.logical;
            } else if (io.KeyShift && !a.selected.empty()) {
                auto i0 = std::find(g_visible.begin(), g_visible.end(), a.selected);
                if (i0 != g_visible.end()) {
                    // Range from the anchor to here (only rows drawn so far + this one; good enough top-down).
                    a.multi.clear();
                    for (auto it = i0; it != g_visible.end(); ++it) a.multi.insert(*it);
                }
            } else if (a.selected == k.logical && a.multi.empty() && !dbl) {
                select_only(a, "");  // click again to deselect
            } else {
                select_only(a, k.logical);
            }
        }
        if (dbl) {
            if (k.dir) navigate(a, k.logical);
            else quick_look(a, k);
        }
        ImGui::TableNextColumn();
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("%s", format_local_time(k.mtime).c_str());
        ImGui::TableNextColumn();
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("%s", k.dir ? "—" : human_size(k.size).c_str());
        ImGui::TableNextColumn();
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("%s", tr(k.dir ? "Folder" : file_type_label(k.name)));
        ImGui::TableNextColumn();
        ImGui::AlignTextToFramePadding();
        if (k.dir && k.tracked_root) {
            status_dot(P.green, 3.5f, ImGui::GetStyle().FramePadding.y);
            ImGui::SameLine(0, 6);
            ImGui::TextDisabled("%s", tr("Synced folder"));
            tip(trf("Kept in sync with %s", k.tracked_info.c_str()));
        } else if (!k.dir && !k.status.empty()) {
            status_dot(status_color(k.status), 3.5f, ImGui::GetStyle().FramePadding.y);
            ImGui::SameLine(0, 6);
            ImGui::TextDisabled("%s", tr(k.status));
            tip(status_help(k.status));
        }
        if (k.dir && open) {
            draw_rows(a, k, depth + 1);
            ImGui::TreePop();
        }
        ImGui::PopID();
    }
}

static void list_keys(App& a, const Node* folder) {
    ImGuiIO& io = ImGui::GetIO();
    if (!a.modal.empty() || io.WantTextInput) return;
    auto pressed = [](ImGuiKey k) { return ImGui::IsKeyPressed(k); };
    const Node* sel = a.selected.empty() ? nullptr : find_node(a.tree.get(), a.selected);
    // Arrow keys move the selection through the visible rows.
    if ((pressed(ImGuiKey_DownArrow) || pressed(ImGuiKey_UpArrow)) && !g_visible.empty() && !io.KeyAlt) {
        auto it = std::find(g_visible.begin(), g_visible.end(), a.selected);
        int i = it == g_visible.end() ? -1 : int(it - g_visible.begin());
        i = pressed(ImGuiKey_DownArrow) ? std::min(int(g_visible.size()) - 1, i + 1) : std::max(0, i - 1);
        select_only(a, g_visible[size_t(i)]);
    }
    if (pressed(ImGuiKey_Escape)) select_only(a, "");
    if (sel && (pressed(ImGuiKey_F2) || pressed(ImGuiKey_Enter) || pressed(ImGuiKey_KeypadEnter))) begin_rename(a, sel->logical);
    if (sel && pressed(ImGuiKey_Space)) quick_look(a, *sel);
    if (sel && !sel->dir && io.KeyCtrl && (pressed(ImGuiKey_E) || pressed(ImGuiKey_O))) open_in_editor(a, sel->entry);
    if (sel && sel->dir && io.KeyCtrl && (pressed(ImGuiKey_DownArrow) || pressed(ImGuiKey_O))) navigate(a, sel->logical);
    if (pressed(ImGuiKey_Delete) || (io.KeyCtrl && pressed(ImGuiKey_Backspace))) begin_delete(a);
    if ((pressed(ImGuiKey_Backspace) && !io.KeyCtrl) || (io.KeyAlt && pressed(ImGuiKey_UpArrow)) || (io.KeyCtrl && pressed(ImGuiKey_UpArrow)))
        if (!a.cwd.empty()) navigate(a, path_dirname(a.cwd));
    if (io.KeyAlt && pressed(ImGuiKey_LeftArrow) && !a.back.empty()) {
        a.fwd.push_back(a.cwd);
        std::string d = a.back.back();
        a.back.pop_back();
        navigate(a, d, false);
    }
    if (io.KeyAlt && pressed(ImGuiKey_RightArrow) && !a.fwd.empty()) {
        a.back.push_back(a.cwd);
        std::string d = a.fwd.back();
        a.fwd.pop_back();
        navigate(a, d, false);
    }
    if (io.KeyCtrl && pressed(ImGuiKey_A) && folder) {
        a.multi.clear();
        for (auto& k : folder->kids) a.multi.insert(k->logical);
    }
    if (io.KeyCtrl && pressed(ImGuiKey_F)) a.focus_search = true;
    if (io.KeyCtrl && pressed(ImGuiKey_U)) choose_and_upload(a);
    if (io.KeyCtrl && io.KeyShift && pressed(ImGuiKey_N)) { a.text_buf[0] = 0; a.modal = "new-folder"; }
    if (io.KeyCtrl && pressed(ImGuiKey_I)) { a.cfg.ui.inspector = !a.cfg.ui.inspector; save_settings(a); }
    if ((io.KeyCtrl && pressed(ImGuiKey_R)) || pressed(ImGuiKey_F5)) refresh_listing(a);
}

static void list(App& a, float width, float height) {
    const Node* folder = current_folder(a);
    bool searching = a.filter[0] || a.type_filter;
    const Node* shown = searching ? a.tree.get() : folder;
    ImGui::BeginChild("##list", ImVec2(width, height), ImGuiChildFlags_None, ImGuiWindowFlags_None);
    g_visible.clear();
    if (!a.tree) {
        empty_state(ICON_FA_CLOUD, "Loading…", "Reading the vault listing");
    } else if (!shown) {
        empty_state(ICON_FA_FOLDER_CLOSED, "This folder no longer exists", "It was moved or deleted on another device.");
        if (!a.cwd.empty()) navigate(a, path_dirname(a.cwd), false);
    } else if (shown->kids.empty()) {
        if (searching) empty_state(ICON_FA_MAGNIFYING_GLASS, "No Results", "Nothing in the vault matches this search.");
        else empty_state(ICON_FA_FOLDER_OPEN, "This folder is empty", "Drop files onto the window, or click the upload button.");
    } else {
        ImGuiTableFlags tf = ImGuiTableFlags_Sortable | ImGuiTableFlags_Resizable | ImGuiTableFlags_Hideable | ImGuiTableFlags_Reorderable |
                             ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_PadOuterX | ImGuiTableFlags_NoBordersInBody;
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(6, 4));
        if (ImGui::BeginTable("##files", 5, tf, ImVec2(0, 0))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            // All columns stretch by weight, so the name always gets most of the width.
            ImGui::TableSetupColumn(tr("Name"), ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_DefaultSort, 3.2f, 0);
            ImGui::TableSetupColumn(tr("Date Modified"), ImGuiTableColumnFlags_WidthStretch, 1.35f, 3);
            ImGui::TableSetupColumn(tr("Size"), ImGuiTableColumnFlags_WidthStretch, 0.7f, 2);
            ImGui::TableSetupColumn(tr("Kind"), ImGuiTableColumnFlags_WidthStretch, 0.75f, 1);
            ImGui::TableSetupColumn(tr("Status"), ImGuiTableColumnFlags_WidthStretch, 1.1f, 4);
            // Quiet header: dim labels on the card colour, a single divider underneath.
            ImGui::TableNextRow(ImGuiTableRowFlags_Headers);
            for (int c = 0; c < 5; c++) {
                ImGui::TableSetColumnIndex(c);
                ImGui::PushStyleColor(ImGuiCol_Text, P.dim);
                ImGui::TableHeader(ImGui::TableGetColumnName(c));
                ImGui::PopStyleColor();
            }
            if (ImGuiTableSortSpecs* ss = ImGui::TableGetSortSpecs(); ss && ss->SpecsDirty) {
                if (ss->SpecsCount > 0) {
                    a.sort_col = int(ss->Specs[0].ColumnUserID);
                    a.sort_desc = ss->Specs[0].SortDirection == ImGuiSortDirection_Descending;
                }
                ss->SpecsDirty = false;
                a.tree_dirty = true;
            }
            draw_rows(a, *shown, 0);
            bool empty_click = ImGui::IsWindowHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Left) && !ImGui::IsAnyItemHovered();
            if (empty_click) select_only(a, "");
            ImGui::EndTable();
        }
        ImGui::PopStyleVar();
    }
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) || !ImGui::IsAnyItemActive()) list_keys(a, folder);
    ImGui::EndChild();
}

static void status_bar(App& a, float width) {
    const Node* folder = current_folder(a);
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 14);
    ImGui::AlignTextToFramePadding();
    size_t items = folder ? folder->kids.size() : 0;
    size_t nsel = a.multi.empty() ? (a.selected.empty() ? 0 : 1) : a.multi.size();
    std::string s = tr_n(items, "%zu item", "%zu items");
    if (nsel) s += " · " + trf("%d selected", int(nsel));
    if (folder) s += " · " + human_size(folder->size);
    small_dim("%s", s.c_str());
    if (a.listed_at) {
        std::string u = trf("Updated %s", format_local_time(a.listed_at).c_str());
        ImGui::SameLine(std::max(0.0f, width - ImGui::CalcTextSize(u.c_str()).x - 24));
        small_dim("%s", u.c_str());
    }
}

// ---------------------------------------------------------------------------------------------------
// inspector

static void kv(const char* k, const std::string& v, const ImVec4* c = nullptr) {
    ImGui::TableNextRow();
    ImGui::TableNextColumn();
    ImGui::TextDisabled("%s", tr(k));
    ImGui::TableNextColumn();
    ImGui::PushTextWrapPos(0.0f);
    if (c) status_text(*c, v.c_str());
    else ImGui::TextUnformatted(tr(v));
    ImGui::PopTextWrapPos();
}

static void big_icon(const char* icon, const ImVec4& c, float scale = 4.0f) {
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * scale);
    float w = ImGui::CalcTextSize(icon).x;
    ImGui::SetCursorPosX((ImGui::GetContentRegionAvail().x - w) / 2 + ImGui::GetCursorPosX());
    ImGui::TextColored(c, "%s", icon);
    ImGui::PopFont();
}

static void centered_text(const std::string& t, float scale = 1.0f, const ImVec4* c = nullptr) {
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * scale);
    float avail = ImGui::GetContentRegionAvail().x;
    float w = ImGui::CalcTextSize(t.c_str()).x;
    if (w <= avail) {
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (avail - w) / 2);
        if (c) ImGui::TextColored(*c, "%s", t.c_str());
        else ImGui::TextUnformatted(t.c_str());
    } else {
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + avail);
        ImGui::TextWrapped("%s", t.c_str());
        ImGui::PopTextWrapPos();
    }
    ImGui::PopFont();
}

static void inspector(App& a, float width, float height) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, P.card);
    ImGui::BeginChild("##inspector", ImVec2(width, height), ImGuiChildFlags_None, ImGuiWindowFlags_None);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wp = ImGui::GetWindowPos();
    dl->AddLine(wp, ImVec2(wp.x, wp.y + height), col(P.border));
    ImGui::SetCursorPos(ImVec2(18, 16));
    ImGui::BeginGroup();
    ImGui::PushItemWidth(width - 36);
    float inner = width - 36;
    ImGui::Dummy(ImVec2(inner, 0));

    const Node* n = a.selected.empty() ? nullptr : find_node(a.tree.get(), a.selected);
    size_t nmulti = a.multi.size();
    if (nmulti > 1) {
        ImGui::Dummy(ImVec2(0, 30));
        big_icon(ICON_FA_LAYER_GROUP, P.dim, 3.5f);
        uint64_t total = 0;
        for (auto& m : a.multi)
            if (const Node* x = find_node(a.tree.get(), m)) total += x->size;
        centered_text(tr_n(nmulti, "%zu item selected", "%zu items selected"), 1.15f);
        centered_text(human_size(total), 0.92f, &P.dim);
        ImGui::Dummy(ImVec2(0, 14));
        if (button(ICON_FA_TRASH "  Move to Trash", Btn::Destructive, ImVec2(inner, 0))) a.modal = "delete-multi";
    } else if (!n) {
        // The current folder.
        const Node* f = current_folder(a);
        ImGui::Dummy(ImVec2(0, 30));
        big_icon(a.cwd.empty() ? ICON_FA_VAULT : ICON_FA_FOLDER, a.cwd.empty() ? P.accent : P.folder, 4.0f);
        centered_text(folder_title(a.cwd), 1.2f);
        if (f) centered_text(tr_n(f->kids.size(), "%zu item", "%zu items") + " · " + human_size(f->size), 0.92f, &P.dim);
        if (f && f->tracked) {
            ImGui::Dummy(ImVec2(0, 6));
            std::string t = std::string(ICON_FA_ARROWS_ROTATE "  ") + (f->tracked_root ? "Synced with " : "Inside ") + f->tracked_info;
            centered_text(t, 0.9f, &P.green);
        }
        ImGui::Dummy(ImVec2(0, 18));
        if (button(ICON_FA_CLOUD_ARROW_UP "  Upload Here…", Btn::Primary, ImVec2(inner, 0))) choose_and_upload(a);
        if (button(ICON_FA_FOLDER_PLUS "  New Folder…", Btn::Secondary, ImVec2(inner, 0))) {
            a.text_buf[0] = 0;
            a.modal = "new-folder";
        }
        ImGui::Dummy(ImVec2(0, 10));
        ImGui::PushStyleColor(ImGuiCol_Text, P.dim);
        ImGui::TextWrapped("%s", tr("Select a file to see its details. Nothing is downloaded or decrypted until you ask for a preview."));
        ImGui::PopStyleColor();
    } else {
        // Preview area / big icon
        bool locked = !n->dir && n->entry.encrypted && key_needed(a);
        bool showing = !n->dir && a.preview.state != PreviewState::Empty && a.preview.logical == n->logical;
        if (showing) {
            draw_preview(a, n, std::min(height * 0.52f, inner * 1.1f));
        } else {
            ImGui::Dummy(ImVec2(0, 18));
            big_icon(type_icon(n->name, n->dir), type_color(n->name, n->dir), 4.0f);
            ImGui::Dummy(ImVec2(0, 4));
            if (!n->dir && preview_kind(n->name) != PreviewKind::None) {
                float bw = 150;
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (inner - bw) / 2);
                if (locked) {
                    if (button(ICON_FA_LOCK "  Unlock to Preview", Btn::Secondary, ImVec2(bw + 30, 0))) a.modal = "unlock";
                } else if (button(ICON_FA_EYE "  Quick Look", Btn::Secondary, ImVec2(bw, 0))) {
                    preview_load(a, n->entry);
                }
                tip("Space");
            }
        }
        ImGui::Dummy(ImVec2(0, 8));
        centered_text(n->name, 1.15f);
        std::string sub = std::string(tr(n->dir ? "Folder" : file_type_label(n->name))) + " · " + human_size(n->size);
        centered_text(sub, 0.9f, &P.dim);
        ImGui::Dummy(ImVec2(0, 10));

        // Actions
        if (n->dir) {
            if (button(ICON_FA_FOLDER_OPEN "  Open", Btn::Primary, ImVec2(inner, 0))) navigate(a, n->logical);
        } else {
            float half = (inner - 8) / 2;
            bool text = preview_kind(n->name) == PreviewKind::Text;
            if (button(ICON_FA_PEN_TO_SQUARE "  Edit", Btn::Secondary, ImVec2(half, 0), text)) open_in_editor(a, n->entry);
            tip(text ? "Built-in editor; the text never leaves memory" : "Only text files can be edited");
            ImGui::SameLine(0, 8);
            if (button(ICON_FA_DOWNLOAD "  Download", Btn::Secondary, ImVec2(half, 0))) download_to_dialog(a, n->entry);
        }
        {
            float half = (inner - 8) / 2;
            if (button(ICON_FA_PEN "  Rename", Btn::Secondary, ImVec2(half, 0))) begin_rename(a, n->logical);
            ImGui::SameLine(0, 8);
            if (button(ICON_FA_TRASH "  Trash", Btn::Destructive, ImVec2(half, 0))) {
                a.modal_arg = n->logical;
                a.modal = "delete";
            }
        }
        ImGui::Dummy(ImVec2(0, 10));

        // Info
        small_dim("INFORMATION");
        {  // hairline the width of the column (Separator would run to the window edge)
            ImVec2 p = ImGui::GetCursorScreenPos();
            ImGui::GetWindowDrawList()->AddLine(p, ImVec2(p.x + inner, p.y), col(P.divider));
            ImGui::Dummy(ImVec2(inner, 3));
        }
        if (ImGui::BeginTable("##info", 2, ImGuiTableFlags_SizingStretchProp, ImVec2(inner, 0))) {
            ImGui::TableSetupColumn("k", ImGuiTableColumnFlags_WidthFixed, ImGui::CalcTextSize("Synced with").x + 18);
            ImGui::TableSetupColumn("v", ImGuiTableColumnFlags_WidthStretch);
            kv("Kind", n->dir ? "Folder" : file_type_label(n->name));
            kv("Size", human_size(n->size) + (n->dir || !n->entry.encrypted ? std::string() : " " + std::string(tr("(encrypted)"))));
            kv("Modified", format_local_time(n->mtime));
            kv("Where", "/" + (path_dirname(n->logical).empty() ? std::string() : path_dirname(n->logical)));
            if (!n->dir) {
                ImVec4 enc_c = n->entry.encrypted ? P.green : P.dim;
                kv("Encryption", n->entry.encrypted ? "OpenPGP · AES-256" : "None", &enc_c);
                if (!n->status.empty()) {
                    ImVec4 sc = status_color(n->status);
                    kv("Status", n->status, &sc);
                }
            }
            if (n->tracked) kv("Synced with", n->tracked_info);
            ImGui::EndTable();
        }
        if (!n->dir && status_help(n->status)[0]) {
            ImGui::Dummy(ImVec2(0, 2));
            ImGui::PushStyleColor(ImGuiCol_Text, P.dim);
            ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + inner);
            ImGui::TextWrapped("%s", tr(status_help(n->status)));
            ImGui::PopTextWrapPos();
            ImGui::PopStyleColor();
        }
    }
    ImGui::PopItemWidth();
    ImGui::EndGroup();
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

// ---------------------------------------------------------------------------------------------------

void draw_files_view(App& a) {
    float W = ImGui::GetWindowWidth(), H = ImGui::GetWindowHeight();
    toolbar(a);
    float top = 52;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wp = ImGui::GetWindowPos();
    dl->AddLine(ImVec2(wp.x, wp.y + top - 1), ImVec2(wp.x + W, wp.y + top - 1), col(P.divider));

    // Locked banner: browsing names only.
    if (key_needed(a)) {
        ImGui::SetCursorPos(ImVec2(0, top));
        ImVec2 p = ImGui::GetCursorScreenPos();
        float bh = 38;
        dl->AddRectFilled(p, ImVec2(p.x + W, p.y + bh), col(P.yellow, P.dark ? 0.12f : 0.18f));
        ImGui::SetCursorPos(ImVec2(16, top + (bh - ImGui::GetFrameHeight()) / 2));
        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(P.dark ? P.yellow : ImVec4(0.55f, 0.4f, 0, 1), "%s", tr(ICON_FA_LOCK "  Encrypted files are locked — you can see names, not contents, and they don't sync."));
        ImGui::SameLine(W - 120);
        if (button("Unlock…", Btn::Primary, ImVec2(100, 0))) a.modal = "unlock";
        top += bh;
    }

    float status_h = 28;
    bool insp = a.cfg.ui.inspector != 0 && W > 760;
    float iw = insp ? std::clamp(a.inspector_w, 260.0f, W * 0.5f) : 0;
    ImGui::SetCursorPos(ImVec2(0, top));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, P.card);
    ImGui::BeginChild("##listwrap", ImVec2(W - iw, H - top), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar);
    ImGui::PopStyleColor();
    list(a, W - iw, H - top - status_h);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, P.bg);
    ImGui::BeginChild("##status", ImVec2(W - iw, status_h));
    ImGui::SetCursorPosY((status_h - ImGui::GetFrameHeight()) / 2);
    status_bar(a, W - iw);
    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::EndChild();
    if (insp) {
        // Splitter
        ImGui::SetCursorPos(ImVec2(W - iw - 3, top));
        ImGui::InvisibleButton("##split", ImVec2(6, H - top));
        if (ImGui::IsItemHovered() || ImGui::IsItemActive()) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
        if (ImGui::IsItemActive()) a.inspector_w = std::clamp(a.inspector_w - ImGui::GetIO().MouseDelta.x, 260.0f, W * 0.5f);
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) a.inspector_w = 330;  // reset
        if (ImGui::IsItemDeactivated() || (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0))) {
            a.cfg.ui.inspector_w = a.inspector_w;
            save_settings(a);
        }
        if (ImGui::IsItemHovered() || ImGui::IsItemActive()) {
            ImVec2 sp = ImGui::GetItemRectMin();
            ImGui::GetForegroundDrawList()->AddLine(ImVec2(sp.x + 3, sp.y), ImVec2(sp.x + 3, sp.y + H - top), col(P.accent), 2);
        }
        ImGui::SetCursorPos(ImVec2(W - iw, top));
        inspector(a, iw, H - top);
    }
}

}  // namespace s3v::ui
