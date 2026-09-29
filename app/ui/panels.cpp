// Tabs and modal dialogs.
#include <GLFW/glfw3.h>
#include <dirent.h>

#include <algorithm>
#include <cstring>
#include <ctime>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "imgui.h"
#include "platform.h"
#include "secret/strength.h"
#include "util/fs.h"
#include "util/secure.h"
#include "util/sha256.h"
#include "util/strings.h"
#include "util/subprocess.h"

namespace s3v::ui {

static const ImVec4 kWarn(1.0f, 0.75f, 0.3f, 1), kErr(1.0f, 0.45f, 0.4f, 1), kOk(0.45f, 0.85f, 0.5f, 1);

const char* type_icon(const std::string& logical, bool dir, bool open) {
    if (dir) return open ? ICON_FA_FOLDER_OPEN : ICON_FA_FOLDER;
    std::string t = file_type_label(logical);
    if (t == "Text") return ICON_FA_FILE_LINES;
    if (t == "Code") return ICON_FA_FILE_CODE;
    if (t == "Image") return ICON_FA_FILE_IMAGE;
    if (t == "PDF") return ICON_FA_FILE_PDF;
    if (t == "Audio") return ICON_FA_FILE_AUDIO;
    if (t == "Video") return ICON_FA_FILE_VIDEO;
    if (t == "Archive") return ICON_FA_FILE_ZIPPER;
    if (t == "Document") return ICON_FA_FILE_WORD;
    return ICON_FA_FILE;
}

bool strength_meter(const char* pw, int min_len) {
    Strength s = check_password(pw, min_len);
    const char* labels[] = {"very weak", "weak", "fair", "strong", "very strong"};
    ImVec4 col = s.score >= 3 ? kOk : s.score == 2 ? kWarn : kErr;
    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, col);
    ImGui::ProgressBar(float(s.score + 1) / 5.0f, ImVec2(-1, 0), pw[0] ? labels[s.score] : "");
    ImGui::PopStyleColor();
    if (pw[0])
        for (auto& p : s.problems) ImGui::TextColored(kWarn, "  • %s", p.c_str());
    return s.acceptable;
}

static void wipe_buf(char* b, size_t n) { explicit_bzero(b, n); }

static std::string join_logical(const std::string& dir, const std::string& name) {
    return dir.empty() ? name : dir + "/" + name;
}

// ---------------------------------------------------------------------------
// vault operations started from the UI

void start_uploads(App& a, const std::vector<std::string>& files) {
    if (a.conn != App::Conn::Ready) {
        a.notify("Not connected", true);
        return;
    }
    a.pending_uploads = files;
    snprintf(a.text_buf, sizeof a.text_buf, "%s", a.current_dir.c_str());
    a.upload_encrypt = a.vault_has_key;
    a.modal = "upload";
}

void upload_files(App& a, std::vector<std::string> files, std::string dest_dir, bool encrypt, int on_exists) {
    auto v = a.vault;
    a.run_job([&a, v, files, dest_dir, encrypt, on_exists] {
        // Expand folders, keeping their structure under dest_dir.
        std::vector<std::pair<std::string, std::string>> items;  // local, logical
        std::function<void(const std::string&, const std::string&)> walk = [&](const std::string& p, const std::string& logical) {
            FileStat st = stat_path(p, true);
            if (st.is_file) {
                items.push_back({p, logical});
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
        std::vector<RemoteEntry> all;
        v->refresh(&all);
        std::map<std::string, RemoteEntry> by;
        for (auto& e : all)
            if (!e.dir_marker) by[e.logical] = e;
        int ok = 0, skipped = 0, failed = 0;
        std::string last_err;
        for (auto& [local, logical] : items) {
            bool enc = encrypt || ends_with(logical, ".gpg");
            Conditions c;
            std::string key;
            auto it = by.find(logical);
            if (it != by.end()) {
                if (on_exists == 2) { skipped++; continue; }
                if (on_exists == 1) {
                    std::string alt = Vault::conflict_name(logical, "uploaded");
                    key = v->key_for(alt, enc);
                    c.if_none_match = true;
                } else {
                    key = it->second.key;  // overwrite keeps the existing form
                    c.if_match = it->second.etag;
                }
            } else {
                key = v->key_for(logical, enc);
                c.if_none_match = true;
            }
            OpResult r = v->upload_file(local, key, c);
            if (r.ok) ok++;
            else { failed++; last_err = r.error; }
        }
        v->refresh();
        a.post([&a, ok, skipped, failed, last_err] {
            a.tree_dirty = true;
            std::string m = "Uploaded " + std::to_string(ok) + " file(s)";
            if (skipped) m += ", skipped " + std::to_string(skipped);
            if (failed) m += ", " + std::to_string(failed) + " failed: " + last_err;
            a.notify(m, failed > 0);
            if (a.engine) a.engine->request_sync();
        });
    });
}

void open_in_editor(App& a, const RemoteEntry& e, bool force) {
    if (!force && preview_kind(e.logical) != PreviewKind::Text) {
        a.modal = "force-edit";
        a.modal_arg = e.logical;
        return;
    }
    if (e.encrypted && !a.vault->unlocked()) {
        a.modal = "unlock";
        return;
    }
    size_t cap = size_t(a.cfg.preview.text_max_mb) << 20;
    if (e.size > cap * 8) {
        a.notify("File too large to edit as text (" + human_size(e.size) + ")", true);
        return;
    }
    auto em = a.edits;
    a.run_job([&a, em, e] {
        std::string err;
        int id = em->open(e, err);
        a.post([&a, id, err, name = e.logical] {
            if (!id) a.notify("Cannot edit " + name + ": " + err, true);
            else if (!err.empty()) a.notify("Editor did not start: " + err + " (see Settings → Dependencies)", true);
            else a.notify("Opened " + name + " in your editor; you will be asked before anything is saved back");
        });
    });
}

void open_externally(App& a, const RemoteEntry& e) {
    if (e.encrypted && !a.vault->unlocked()) {
        a.modal = "unlock";
        return;
    }
    if (!a.open_warning_shown && e.encrypted) {
        a.modal = "open-warning";
        a.modal_arg = e.logical;
        return;
    }
    auto v = a.vault;
    std::string opener = a.cfg.deps.opener;
    a.run_job([&a, v, e, opener] {
        std::string dir = platform::session_tmp_dir() + "/open/" + to_hex(random_bytes(6));
        mkdirs(dir, 0700);
        std::string path = dir + "/" + path_basename(e.logical);
        OpResult r = v->download_to(e.key, path);
        bool ok = r.ok && platform::open_external(opener, path);
        a.post([&a, ok, err = r.ok ? "cannot start " + opener : r.error] {
            if (!ok) a.notify(err, true);
        });
    });
}

static void download_to_dialog(App& a, const RemoteEntry& e) {
    if (e.encrypted && !a.vault->unlocked()) {
        a.modal = "unlock";
        return;
    }
    auto v = a.vault;
    browse(a, BrowseMode::Save, "Download " + path_basename(e.logical), [&a, v, e](std::vector<std::string> paths) {
        std::string dest = paths[0];
        a.run_job([&a, v, e, dest] {
            OpResult r = v->download_to(e.key, dest);
            a.post([&a, r, dest] { a.notify(r.ok ? "Saved " + dest : r.error, !r.ok); });
        });
    }, path_basename(e.logical));
}

// ---------------------------------------------------------------------------
// vault tab

static void context_menu(App& a, const Node& n) {
    if (!ImGui::BeginPopupContextItem()) return;
    a.selected = n.logical;
    if (!n.dir) {
        const RemoteEntry& e = n.entry;
        bool previewable = preview_kind(e.logical) != PreviewKind::None;
        if (ImGui::MenuItem(ICON_FA_EYE "  Preview", nullptr, false, previewable)) preview_load(a, e);
        if (ImGui::MenuItem(ICON_FA_PEN_TO_SQUARE "  Edit in text editor", nullptr, false, preview_kind(e.logical) == PreviewKind::Text))
            open_in_editor(a, e, false);
        if (ImGui::MenuItem(ICON_FA_PEN "  Force open in text editor…")) open_in_editor(a, e, false);
        if (ImGui::MenuItem(ICON_FA_FILE_EXPORT "  Open with default app")) open_externally(a, e);
        if (ImGui::MenuItem(ICON_FA_DOWNLOAD "  Download to…")) download_to_dialog(a, e);
        ImGui::Separator();
    } else {
        if (ImGui::MenuItem(ICON_FA_UPLOAD "  Upload files here…")) {
            a.current_dir = n.logical;
            browse(a, BrowseMode::OpenMany, "Upload to /" + n.logical, [&a](std::vector<std::string> f) { start_uploads(a, f); });
        }
        if (ImGui::MenuItem(ICON_FA_FOLDER_PLUS "  New folder here…")) {
            a.current_dir = n.logical;
            a.text_buf[0] = 0;
            a.modal = "new-folder";
        }
        ImGui::Separator();
    }
    if (ImGui::MenuItem(ICON_FA_PEN "  Rename / move…")) {
        snprintf(a.text_buf, sizeof a.text_buf, "%s", n.logical.c_str());
        a.modal_arg = n.logical;
        a.modal = "rename";
    }
    if (ImGui::MenuItem(ICON_FA_TRASH "  Delete…")) {
        a.modal_arg = n.logical;
        a.modal = "delete";
    }
    ImGui::EndPopup();
}

static const char* status_icon(const std::string& s) {
    if (s == "Synced") return ICON_FA_CIRCLE_CHECK;
    if (s == "Pending") return ICON_FA_ARROWS_ROTATE;
    if (s == "Conflict") return ICON_FA_TRIANGLE_EXCLAMATION;
    if (s == "Paused") return ICON_FA_CIRCLE_PAUSE;
    if (s == "Cloud only") return ICON_FA_CLOUD;
    return "";
}

static void draw_node(App& a, const Node& n) {
    for (auto& kp : n.kids) {
        const Node& k = *kp;
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::PushID(k.logical.c_str());
        bool sel = a.selected == k.logical || a.multi.count(k.logical);
        ImGuiTreeNodeFlags f = ImGuiTreeNodeFlags_SpanAllColumns | ImGuiTreeNodeFlags_OpenOnArrow |
                               ImGuiTreeNodeFlags_OpenOnDoubleClick | (sel ? ImGuiTreeNodeFlags_Selected : 0);
        if (!k.dir) f |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
        if (a.filter[0] || a.type_filter) f |= ImGuiTreeNodeFlags_DefaultOpen;
        if (k.dir && a.force_open.erase(k.logical)) ImGui::SetNextItemOpen(true);
        bool open = ImGui::TreeNodeEx("##n", f);
        bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left) && !ImGui::IsItemToggledOpen();
        bool dbl = ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
        context_menu(a, k);
        ImGui::SameLine();
        ImGui::Text("%s %s", type_icon(k.logical, k.dir, open && k.dir), k.name.c_str());
        if (!k.dir && k.entry.encrypted) {
            ImGui::SameLine();
            ImGui::TextDisabled(ICON_FA_LOCK);
        }
        if (clicked) {
            if (ImGui::GetIO().KeyCtrl) {
                if (!a.multi.erase(k.logical)) a.multi.insert(k.logical);
            } else {
                a.multi.clear();
                if (a.selected != k.logical) {
                    // Selecting something else frees any open preview: nothing stays decrypted unasked.
                    if (a.preview.state != PreviewState::Empty) preview_free(a);
                    a.selected = k.logical;
                }
                a.current_dir = k.dir ? k.logical : path_dirname(k.logical);
            }
        }
        if (dbl && !k.dir && preview_kind(k.logical) != PreviewKind::None) preview_load(a, k.entry);
        ImGui::TableNextColumn();
        ImGui::TextDisabled("%s", k.dir ? "Folder" : file_type_label(k.logical));
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(human_size(k.size).c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(format_local_time(k.mtime).c_str());
        ImGui::TableNextColumn();
        if (!k.dir && !k.status.empty()) {
            ImVec4 col = k.status == "Conflict" ? kWarn : k.status == "Synced" ? kOk : ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled);
            ImGui::TextColored(col, "%s %s", status_icon(k.status), k.status.c_str());
        }
        if (k.dir && open) {
            draw_node(a, k);
            ImGui::TreePop();
        }
        ImGui::PopID();
    }
}

static void details_pane(App& a) {
    const Node* n = a.selected.empty() ? nullptr : find_node(a.tree.get(), a.selected);
    if (!n) {
        ImGui::TextDisabled("Select a file to see its details.");
        ImGui::TextDisabled("Nothing is downloaded or decrypted until you click Preview.");
        return;
    }
    ImGui::Text("%s %s", type_icon(n->logical, n->dir, false), n->name.c_str());
    ImGui::TextDisabled("/%s", n->logical.c_str());
    ImGui::Separator();
    if (n->dir) {
        ImGui::Text("Folder · %s", human_size(n->size).c_str());
        ImGui::Text("Last modified: %s", format_local_time(n->mtime).c_str());
        return;
    }
    const RemoteEntry& e = n->entry;
    if (ImGui::BeginTable("meta", 2, ImGuiTableFlags_SizingFixedFit)) {
        auto row = [](const char* k, const std::string& v) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", k);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(v.c_str());
        };
        row("Type", file_type_label(e.logical));
        row("Size", human_size(e.size) + (e.encrypted ? " (encrypted)" : ""));
        row("Last modified", format_local_time(e.mtime));
        row("Encryption", e.encrypted ? "OpenPGP (gpg), vault key" : "none");
        row("Status", n->status);
        ImGui::EndTable();
    }
    bool locked = e.encrypted && !a.vault->unlocked();
    PreviewKind pk = preview_kind(e.logical);
    if (locked) ImGui::TextColored(kWarn, ICON_FA_LOCK " Unlock the vault to preview, edit or download this file.");
    ImGui::BeginDisabled(pk == PreviewKind::None);
    if (ImGui::Button(ICON_FA_EYE " Preview")) {
        if (locked) a.modal = "unlock";
        else preview_load(a, e);
    }
    ImGui::EndDisabled();
    if (pk == PreviewKind::None && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Preview supports text, images (png/jpg/gif/bmp/tga/psd) and PDF");
    ImGui::SameLine();
    if (ImGui::Button(ICON_FA_PEN_TO_SQUARE " Edit")) open_in_editor(a, e, false);
    ImGui::SameLine();
    if (ImGui::Button(ICON_FA_FILE_EXPORT " Open")) open_externally(a, e);
    ImGui::SameLine();
    if (ImGui::Button(ICON_FA_DOWNLOAD " Download…")) download_to_dialog(a, e);
    ImGui::Separator();
    draw_preview(a, n);
}

void draw_vault_tab(App& a) {
    if (a.conn != App::Conn::Ready) {
        ImGui::Spacing();
        if (a.conn == App::Conn::Unconfigured) ImGui::TextWrapped("Configure your storage under Settings to get started.");
        else if (a.conn == App::Conn::NoVault) {
            ImGui::TextWrapped("There is no vault at this bucket/prefix yet.");
            if (ImGui::Button("Create vault…")) a.modal = "create-vault";
        } else if (a.conn == App::Conn::Connecting) ImGui::TextDisabled("Connecting…");
        else ImGui::TextColored(kErr, "%s", a.conn_error.c_str());
        return;
    }
    if (ImGui::Button(ICON_FA_UPLOAD " Upload…"))
        browse(a, BrowseMode::OpenMany, "Upload to /" + a.current_dir, [&a](std::vector<std::string> f) { start_uploads(a, f); });
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Or drop files and folders onto the window");
    ImGui::SameLine();
    if (ImGui::Button(ICON_FA_FOLDER_PLUS " New folder")) {
        a.text_buf[0] = 0;
        a.modal = "new-folder";
    }
    ImGui::SameLine();
    if (ImGui::Button(ICON_FA_ARROWS_ROTATE " Refresh")) {
        auto v = a.vault;
        a.run_job([&a, v] {
            OpResult r = v->refresh();
            a.post([&a, r] { a.tree_dirty = true; if (!r.ok) a.notify(r.error, true); });
        });
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220);
    if (ImGui::InputTextWithHint("##filter", ICON_FA_MAGNIFYING_GLASS " Filter by name", a.filter, sizeof a.filter)) a.tree_dirty = true;
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140);
    const char* types[] = {"All types", "Text", "Images", "PDF", "Encrypted"};
    if (ImGui::Combo("##type", &a.type_filter, types, 5)) a.tree_dirty = true;
    if (!a.multi.empty()) {
        ImGui::SameLine();
        if (ImGui::Button((ICON_FA_TRASH " Delete " + std::to_string(a.multi.size()) + " selected").c_str())) {
            a.modal_arg = "";
            a.modal = "delete-multi";
        }
    }
    ImGui::SameLine();
    ImGui::TextDisabled("Destination: /%s", a.current_dir.c_str());

    if (ImGui::BeginTable("split", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV, ImVec2(0, -1))) {
        ImGui::TableSetupColumn("tree", ImGuiTableColumnFlags_WidthStretch, 0.6f);
        ImGui::TableSetupColumn("detail", ImGuiTableColumnFlags_WidthStretch, 0.4f);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGuiTableFlags tf = ImGuiTableFlags_Sortable | ImGuiTableFlags_Resizable | ImGuiTableFlags_Hideable |
                             ImGuiTableFlags_Reorderable | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                             ImGuiTableFlags_BordersV;
        if (ImGui::BeginTable("tree", 5, tf, ImVec2(0, ImGui::GetContentRegionAvail().y))) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_DefaultSort, 0, 0);
            ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 80, 1);
            ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 80, 2);
            ImGui::TableSetupColumn("Last modified", ImGuiTableColumnFlags_WidthFixed, 130, 3);
            ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 100, 4);
            ImGui::TableHeadersRow();
            if (ImGuiTableSortSpecs* ss = ImGui::TableGetSortSpecs(); ss && ss->SpecsDirty) {
                if (ss->SpecsCount > 0) {
                    a.sort_col = int(ss->Specs[0].ColumnUserID);
                    a.sort_desc = ss->Specs[0].SortDirection == ImGuiSortDirection_Descending;
                }
                ss->SpecsDirty = false;
                a.tree_dirty = true;
            }
            if (a.tree) draw_node(a, *a.tree);
            ImGui::EndTable();
        }
        ImGui::TableNextColumn();
        ImGui::BeginChild("details", ImVec2(0, ImGui::GetContentRegionAvail().y));
        details_pane(a);
        ImGui::EndChild();
        ImGui::EndTable();
    }
}

// ---------------------------------------------------------------------------
// tracked folders

void draw_folders_tab(App& a) {
    ImGui::TextWrapped("Tracked folders sync automatically: changes are picked up by the file watcher and the server is polled every %d s.",
                       a.cfg.sync.poll_seconds);
    ImGui::BeginDisabled(a.conn != App::Conn::Ready);
    if (ImGui::Button(ICON_FA_FOLDER_PLUS " Add folder…")) {
        browse(a, BrowseMode::Folder, "Choose a folder to sync", [&a](std::vector<std::string> d) {
            a.modal_arg = d[0];
            snprintf(a.text_buf, sizeof a.text_buf, "%s", path_basename(d[0]).c_str());
            a.upload_encrypt = a.vault_has_key;
            a.upload_on_exists = 0;
            a.modal = "add-root";
        });
    }
    ImGui::EndDisabled();
    if (a.conn != App::Conn::Ready) {
        ImGui::SameLine();
        ImGui::TextDisabled("Connect to your storage first (Settings).");
    }
    ImGui::Spacing();
    auto roots = a.db.roots();
    if (roots.empty()) {
        ImGui::TextDisabled("No tracked folders yet.");
        return;
    }
    if (ImGui::BeginTable("roots", 6, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Local folder", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Vault path", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Direction", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Encrypt new files", ImGuiTableColumnFlags_WidthFixed, 120);
        ImGui::TableSetupColumn("Paused", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableHeadersRow();
        const char* dirs[] = {"two-way", "upload-only", "download-only"};
        for (auto r : roots) {
            ImGui::PushID(r.id);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            bool exists = stat_path(r.local_path, true).is_dir;
            if (!exists) ImGui::TextColored(kErr, ICON_FA_TRIANGLE_EXCLAMATION " %s (missing)", r.local_path.c_str());
            else ImGui::TextUnformatted(r.local_path.c_str());
            ImGui::TableNextColumn();
            ImGui::Text("/%s", r.remote_prefix.c_str());
            ImGui::TableNextColumn();
            int di = r.direction == "upload-only" ? 1 : r.direction == "download-only" ? 2 : 0;
            ImGui::SetNextItemWidth(-1);
            bool changed = false;
            if (ImGui::Combo("##dir", &di, dirs, 3)) { r.direction = dirs[di]; changed = true; }
            ImGui::TableNextColumn();
            if (ImGui::Checkbox("##enc", &r.encrypt)) changed = true;
            ImGui::TableNextColumn();
            if (ImGui::Checkbox("##pause", &r.paused)) changed = true;
            ImGui::TableNextColumn();
            if (ImGui::SmallButton("Remove")) {
                a.modal_arg = std::to_string(r.id);
                a.modal = "remove-root";
            }
            if (changed) {
                a.db.update_root(r);
                if (a.engine) a.engine->request_sync();
                a.tree_dirty = true;
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::Spacing();
    ImGui::TextDisabled("two-way: changes go both ways · upload-only: backup, local deletions are kept on the server · "
                        "download-only: mirror of the server");
    ImGui::TextDisabled("Ignore rules: put a .s3vaultignore (gitignore syntax) in the folder.");
}

// ---------------------------------------------------------------------------
// conflicts

void draw_conflicts_tab(App& a) {
    auto list = a.db.conflicts();
    auto roots = a.db.roots();
    // Drop selections of conflicts that no longer exist.
    std::set<int64_t> live;
    for (auto& c : list) live.insert(c.id);
    for (auto it = a.conflict_sel.begin(); it != a.conflict_sel.end();) it = live.count(*it) ? std::next(it) : a.conflict_sel.erase(it);

    if (list.empty()) {
        ImGui::Spacing();
        ImGui::TextColored(kOk, ICON_FA_CIRCLE_CHECK " No conflicts.");
        ImGui::TextDisabled("When the same file changes on two devices, it is listed here and nothing is overwritten until you decide.");
        return;
    }
    size_t nsel = a.conflict_sel.size();
    ImGui::Text("%zu conflict(s), %zu selected", list.size(), nsel);
    ImGui::SameLine();
    if (ImGui::SmallButton("Select all")) for (auto& c : list) a.conflict_sel.insert(c.id);
    ImGui::SameLine();
    if (ImGui::SmallButton("Select none")) a.conflict_sel.clear();
    ImGui::BeginDisabled(nsel == 0 || a.busy > 0);
    auto act = [&](const char* label, const char* id, const char* tip) {
        ImGui::SameLine();
        if (ImGui::Button(label)) { a.modal_arg = id; a.modal = "resolve"; }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) ImGui::SetTooltip("%s", tip);
    };
    act("Keep both", "keep-both", "The server version is saved next to yours as \"name (conflict remote …)\"");
    act("Overwrite server", "keep-local", "Your local version replaces the server version (the server copy is kept in the vault trash when it is deleted)");
    act("Overwrite local", "keep-remote", "The server version replaces your local file (your local file goes to the desktop trash)");
    act("Keep newest", "keep-newest", "Whichever side was modified last wins");
    ImGui::EndDisabled();
    if (nsel == 1) {
        ImGui::SameLine();
        if (ImGui::Button(ICON_FA_EYE " Compare")) {
            a.modal_arg = std::to_string(*a.conflict_sel.begin());
            a.modal = "compare";
        }
    }
    ImGui::Separator();

    // Group: root → parent dir → file.
    std::map<int, std::map<std::string, std::vector<const ConflictRow*>>> groups;
    for (auto& c : list) groups[c.root_id][path_dirname(c.rel)].push_back(&c);
    auto group_check = [&](const char* id, const std::vector<const ConflictRow*>& items) {
        size_t n = 0;
        for (auto* c : items) n += a.conflict_sel.count(c->id);
        bool all = n == items.size();
        bool mixed = n > 0 && !all;
        if (mixed) ImGui::PushItemFlag(ImGuiItemFlags_MixedValue, true);
        bool v = all;
        if (ImGui::Checkbox(id, &v)) {
            for (auto* c : items) {
                if (v) a.conflict_sel.insert(c->id);
                else a.conflict_sel.erase(c->id);
            }
        }
        if (mixed) ImGui::PopItemFlag();
    };
    if (ImGui::BeginTable("conf", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersV,
                          ImVec2(0, -1))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("File", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("What happened", ImGuiTableColumnFlags_WidthFixed, 190);
        ImGui::TableSetupColumn("This device", ImGuiTableColumnFlags_WidthFixed, 190);
        ImGui::TableSetupColumn("Server", ImGuiTableColumnFlags_WidthFixed, 190);
        ImGui::TableHeadersRow();
        for (auto& [root_id, dirs] : groups) {
            std::string rp = "?";
            for (auto& r : roots) if (r.id == root_id) rp = r.local_path;
            std::vector<const ConflictRow*> all_root;
            for (auto& [d, v] : dirs) all_root.insert(all_root.end(), v.begin(), v.end());
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(root_id);
            group_check("##root", all_root);
            ImGui::SameLine();
            bool ropen = ImGui::TreeNodeEx("##r", ImGuiTreeNodeFlags_DefaultOpen | ImGuiTreeNodeFlags_SpanAllColumns, ICON_FA_HARD_DRIVE " %s", rp.c_str());
            if (ropen) {
                for (auto& [dir, items] : dirs) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::PushID(dir.c_str());
                    group_check("##dir", items);
                    ImGui::SameLine();
                    bool dopen = ImGui::TreeNodeEx("##d", ImGuiTreeNodeFlags_DefaultOpen | ImGuiTreeNodeFlags_SpanAllColumns, ICON_FA_FOLDER " %s/",
                                                   dir.empty() ? "." : dir.c_str());
                    if (dopen) {
                        for (auto* c : items) {
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn();
                            ImGui::PushID(int(c->id));
                            bool s = a.conflict_sel.count(c->id);
                            if (ImGui::Checkbox("##c", &s)) {
                                if (s) a.conflict_sel.insert(c->id);
                                else a.conflict_sel.erase(c->id);
                            }
                            ImGui::SameLine();
                            ImGui::Text("%s %s", type_icon(c->rel, false, false), path_basename(c->rel).c_str());
                            ImGui::TableNextColumn();
                            const char* what = c->kind == "both-modified" ? "changed on both sides"
                                               : c->kind == "both-added"  ? "added on both sides"
                                               : c->kind == "remote-deleted" ? "changed here, deleted on server"
                                               : c->kind == "local-deleted"  ? "deleted here, changed on server"
                                                                             : c->kind.c_str();
                            ImGui::TextColored(kWarn, "%s", what);
                            ImGui::TableNextColumn();
                            if (c->local_exists) ImGui::Text("%s · %s", human_size(c->local_size).c_str(), format_local_time(c->local_mtime).c_str());
                            else ImGui::TextDisabled("deleted");
                            ImGui::TableNextColumn();
                            if (c->remote_exists) ImGui::Text("%s · %s", human_size(c->remote_size).c_str(), format_local_time(c->remote_mtime).c_str());
                            else ImGui::TextDisabled("deleted");
                            ImGui::PopID();
                        }
                        ImGui::TreePop();
                    }
                    ImGui::PopID();
                }
                ImGui::TreePop();
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}

// ---------------------------------------------------------------------------
// transfers / edits

void draw_transfers_tab(App& a) {
    if (!a.engine) return;
    auto ts = a.engine->transfers();
    if (ts.empty()) ImGui::TextDisabled("No transfers running.");
    for (auto& t : ts) {
        float f = t.total ? float(double(t.done) / double(t.total)) : 0.0f;
        std::string lbl = human_size(t.done) + " / " + human_size(t.total);
        ImGui::Text("%s %s", t.what == "upload" ? ICON_FA_CLOUD_ARROW_UP : ICON_FA_CLOUD_ARROW_DOWN, t.path.c_str());
        ImGui::ProgressBar(f, ImVec2(-1, 0), lbl.c_str());
    }
    ImGui::Separator();
    ImGui::TextDisabled("Activity");
    ImGui::BeginChild("log", ImVec2(0, -1), ImGuiChildFlags_Borders);
    auto lines = a.engine->log_lines(500);
    for (auto& l : lines) ImGui::TextUnformatted(l.c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 4) ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
}

void draw_edits_tab(App& a) {
    if (!a.edits) return;
    auto ss = a.edits->sessions();
    static const bool in_ram = platform::session_tmp_in_ram();
    ImGui::TextWrapped("Files opened in your editor. The copy lives in %s and is wiped when you close it here, lock the vault or quit.",
                       in_ram ? "RAM (tmpfs)" : "a temporary folder");
    if (ss.empty()) {
        ImGui::TextDisabled("Nothing open. Use Edit on a file in the Vault tab.");
        return;
    }
    if (ImGui::BeginTable("edits", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH)) {
        ImGui::TableSetupColumn("File", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 220);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 330);
        ImGui::TableHeadersRow();
        for (auto& s : ss) {
            ImGui::PushID(s.id);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("%s %s", type_icon(s.logical, false, false), s.logical.c_str());
            ImGui::TableNextColumn();
            if (s.conflict) ImGui::TextColored(kErr, ICON_FA_TRIANGLE_EXCLAMATION " changed on server");
            else if (s.changed) ImGui::TextColored(kWarn, ICON_FA_PEN " unsaved changes");
            else ImGui::TextDisabled("no changes");
            if (!s.error.empty() && ImGui::IsItemHovered()) ImGui::SetTooltip("%s", s.error.c_str());
            ImGui::TableNextColumn();
            ImGui::BeginDisabled(!s.changed);
            if (ImGui::SmallButton("Save back")) {
                auto em = a.edits;
                int id = s.id;
                a.run_job([&a, em, id] {
                    OpResult r = em->save_back(id);
                    a.post([&a, r, id] {
                        if (r.ok) { a.notify("Saved to the vault"); a.tree_dirty = true; if (a.engine) a.engine->request_sync(); }
                        else if (r.precondition_failed) { a.edit_prompt_id = id; a.modal = "edit-conflict"; }
                        else a.notify(r.error, true);
                    });
                });
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            if (ImGui::SmallButton("Reopen editor")) {
                auto em = a.edits;
                int id = s.id;
                a.run_job([&a, em, id] {
                    std::string err;
                    if (!em->relaunch(id, err)) a.post([&a, err] { a.notify("Editor did not start: " + err, true); });
                });
            }
            ImGui::SameLine();
            if (ImGui::SmallButton(s.changed ? "Discard…" : "Done")) {
                if (s.changed) { a.edit_prompt_id = s.id; a.modal = "edit-discard"; }
                else a.edits->discard(s.id);
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}

// ---------------------------------------------------------------------------
// settings

static void input_str(const char* label, std::string& s, ImGuiInputTextFlags f = 0, const char* hint = nullptr) {
    char buf[512];
    snprintf(buf, sizeof buf, "%s", s.c_str());
    ImGui::SetNextItemWidth(360);
    bool ch = hint ? ImGui::InputTextWithHint(label, hint, buf, sizeof buf, f) : ImGui::InputText(label, buf, sizeof buf, f);
    if (ch) s = buf;
}

static void dep_row(const char* name, const std::string& path, const std::string& detail, bool ok) {
    ImGui::TableNextRow();
    ImGui::TableNextColumn();
    ImGui::TextUnformatted(name);
    ImGui::TableNextColumn();
    if (ok) ImGui::TextColored(kOk, ICON_FA_CHECK " %s", path.c_str());
    else ImGui::TextColored(kErr, ICON_FA_XMARK " %s", path.empty() ? "not found" : path.c_str());
    ImGui::TableNextColumn();
    ImGui::TextDisabled("%s", detail.c_str());
}

void draw_settings_tab(App& a) {
    Config& f = a.form;
    ImGui::BeginChild("settings", ImVec2(0, -ImGui::GetFrameHeightWithSpacing() * 1.4f));
    if (a.conn == App::Conn::Unconfigured)
        ImGui::TextColored(kWarn, ICON_FA_GEAR " Fill in your S3-compatible storage to get started.");

    if (ImGui::CollapsingHeader("Storage", ImGuiTreeNodeFlags_DefaultOpen)) {
        const char* providers[] = {"r2", "aws", "minio", "b2", "wasabi", "custom"};
        int pi = 0;
        for (int i = 0; i < 6; i++) if (f.storage.provider == providers[i]) pi = i;
        ImGui::SetNextItemWidth(360);
        if (ImGui::Combo("Provider", &pi, providers, 6)) f.storage.provider = providers[pi];
        if (f.storage.provider == "r2") input_str("Account ID", f.storage.account_id);
        input_str("Endpoint", f.storage.endpoint, 0, "auto");
        input_str("Region", f.storage.region, 0, "auto");
        const char* addr[] = {"auto", "path", "virtual"};
        int ai = f.storage.addressing == "path" ? 1 : f.storage.addressing == "virtual" ? 2 : 0;
        ImGui::SetNextItemWidth(360);
        if (ImGui::Combo("Addressing", &ai, addr, 3)) f.storage.addressing = addr[ai];
        input_str("Bucket", f.storage.bucket);
        input_str("Vault prefix", f.storage.prefix);
        input_str("Access key ID", f.storage.access_key_id);
        ImGui::SetNextItemWidth(360);
        ImGui::InputTextWithHint("Secret access key", "stored in the keychain, never in config.ini", a.secret_buf, sizeof a.secret_buf,
                                 ImGuiInputTextFlags_Password);
        ImGui::SameLine();
        bool env_secret = getenv("S3VAULT_SECRET_KEY") != nullptr;
        if (env_secret) ImGui::TextDisabled("(using $S3VAULT_SECRET_KEY)");
        ImGui::BeginDisabled(a.probing || a.conn != App::Conn::Ready);
        if (ImGui::Button("Test storage")) {
            a.probing = true;
            a.probe_report.clear();
            auto v = a.vault;
            a.run_job([&a, v] {
                std::string rep;
                S3Client& s = v->s3();
                std::string key = v->prefix() + ".s3vault/probe/" + to_hex(random_bytes(6));
                auto line = [&](const char* what, bool ok, const std::string& d = "") {
                    rep += std::string(ok ? "ok    " : "FAIL  ") + what + (d.empty() ? "" : " — " + d) + "\n";
                };
                S3Result r = s.put_string(key, "1");
                line("PUT", r.ok(), r.ok() ? "" : r.describe());
                if (r.ok()) {
                    Conditions inm;
                    inm.if_none_match = true;
                    S3Result r2 = s.put_string(key, "2", inm);
                    line("conditional create (If-None-Match)", r2.http == 412, r2.http == 412 ? "" : r2.describe());
                    Conditions st;
                    st.if_match = "0000";
                    S3Result r3 = s.put_string(key, "3", st);
                    line("conditional update (If-Match)", r3.http == 412, r3.http == 412 ? "" : r3.describe());
                    S3Result c = s.copy(key, key + ".c");
                    line("server-side copy", c.ok(), c.ok() ? "" : c.describe());
                    s.del(key);
                    s.del(key + ".c");
                }
                a.post([&a, rep] { a.probe_report = rep; a.probing = false; });
            });
        }
        ImGui::EndDisabled();
        if (!a.probe_report.empty()) ImGui::TextUnformatted(a.probe_report.c_str());
    }
    if (ImGui::CollapsingHeader("Dependencies", ImGuiTreeNodeFlags_DefaultOpen)) {
        input_str("gpg", f.deps.gpg, 0, "auto");
        input_str("pdftoppm", f.deps.pdftoppm, 0, "auto");
        input_str("Open with", f.deps.opener);
        input_str("Text editor", f.deps.editor, 0, "auto ($VISUAL, $EDITOR, desktop default)");
        input_str("Terminal (for vim/nano…)", f.deps.terminal);
        // Probed at most every 3 s (running `gpg --version` and PATH lookups every frame would stall the UI).
        struct Deps {
            std::string gpg_cfg, pdf_cfg, gpg_exe, gpg_ver, pdf, info, tmp;
            bool gpg_ok = false, keychain = false, in_ram = false;
            double at = -100;
        };
        static Deps d;
        if (glfwGetTime() - d.at > 3.0 || d.gpg_cfg != f.deps.gpg || d.pdf_cfg != f.deps.pdftoppm) {
            Gpg g(f.deps.gpg);
            d.gpg_cfg = f.deps.gpg;
            d.pdf_cfg = f.deps.pdftoppm;
            d.gpg_exe = g.exe();
            d.gpg_ver = g.version();
            d.gpg_ok = g.available();
            d.pdf = find_executable(f.deps.pdftoppm == "auto" ? "pdftoppm" : f.deps.pdftoppm);
            d.info = find_executable("pdfinfo");
            d.keychain = platform::keychain_available();
            d.tmp = platform::session_tmp_dir();
            d.in_ram = platform::session_tmp_in_ram();
            d.at = glfwGetTime();
        }
        if (ImGui::BeginTable("deps", 3, ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_BordersInnerH)) {
            dep_row("gpg", d.gpg_exe, d.gpg_ok ? "GnuPG " + d.gpg_ver : d.gpg_ver.empty() ? "install gnupg" : d.gpg_ver, d.gpg_ok);
            dep_row("pdftoppm", d.pdf, d.pdf.empty() ? "PDF preview disabled (install poppler-utils)" : "PDF preview", !d.pdf.empty());
            dep_row("pdfinfo", d.info, "PDF page count", !d.info.empty());
            dep_row("keychain", d.keychain ? "Secret Service" : "", "S3 secret and remembered vault key", d.keychain);
            dep_row("temp dir", d.tmp, d.in_ram ? "in RAM (tmpfs)" : "on disk: files are overwritten before deletion", d.in_ram);
            ImGui::EndTable();
        }
    }
    if (ImGui::CollapsingHeader("Security")) {
        const char* modes[] = {"ask", "session", "idle", "keychain"};
        const char* labels[] = {"Ask every time", "Until I lock or quit", "Until idle for N minutes", "In the keychain for N days"};
        int mi = 2;
        for (int i = 0; i < 4; i++) if (f.security.remember == modes[i]) mi = i;
        ImGui::SetNextItemWidth(360);
        if (ImGui::Combo("Remember the password", &mi, labels, 4)) f.security.remember = modes[mi];
        ImGui::SetNextItemWidth(160);
        ImGui::InputInt("Idle minutes", &f.security.idle_minutes);
        ImGui::SetNextItemWidth(160);
        ImGui::InputInt("Keychain days", &f.security.keychain_days);
        ImGui::SetNextItemWidth(160);
        ImGui::InputInt("Minimum password length", &f.security.min_length);
        f.security.min_length = std::max(10, f.security.min_length);
        ImGui::BeginDisabled(a.conn != App::Conn::Ready);
        if (ImGui::Button(a.vault_has_key ? "Change vault password…" : "Set vault password…")) a.modal = a.vault_has_key ? "change-password" : "set-password";
        ImGui::EndDisabled();
        ImGui::TextDisabled("Only the vault key is kept in memory (locked, wiped on lock). Changing the password re-encrypts only key.gpg.");
    }
    if (ImGui::CollapsingHeader("Preview limits")) {
        ImGui::SetNextItemWidth(160); ImGui::InputInt("Text (MB)", &f.preview.text_max_mb);
        ImGui::SetNextItemWidth(160); ImGui::InputInt("Image (MB)", &f.preview.image_max_mb);
        ImGui::SetNextItemWidth(160); ImGui::InputInt("Image (megapixels)", &f.preview.image_max_mpix);
        ImGui::SetNextItemWidth(160); ImGui::InputInt("PDF (MB)", &f.preview.pdf_max_mb);
        ImGui::SetNextItemWidth(160); ImGui::InputInt("PDF DPI", &f.preview.pdf_dpi);
        ImGui::SetNextItemWidth(160); ImGui::InputInt("Free preview after idle (s)", &f.preview.idle_free_seconds);
    }
    if (ImGui::CollapsingHeader("Sync")) {
        input_str("Device name", f.sync.device_name, 0, "hostname");
        ImGui::SetNextItemWidth(160); ImGui::InputInt("Poll server every (s)", &f.sync.poll_seconds);
        ImGui::SetNextItemWidth(160); ImGui::InputInt("Parallel transfers", &f.sync.concurrency);
        ImGui::SetNextItemWidth(160); ImGui::InputInt("Bandwidth limit (KB/s, 0 = none)", &f.sync.bandwidth_kbps);
        ImGui::SetNextItemWidth(160); ImGui::InputInt("Keep vault trash (days)", &f.sync.trash_days);
        ImGui::BeginDisabled(a.conn != App::Conn::Ready);
        if (ImGui::Button("Empty vault trash older than that")) {
            auto v = a.vault;
            int days = f.sync.trash_days;
            a.run_job([&a, v, days] {
                int n = 0;
                OpResult r = v->purge_trash(days, &n);
                a.post([&a, r, n] { a.notify(r.ok ? "Purged " + std::to_string(n) + " object(s)" : r.error, !r.ok); });
            });
        }
        ImGui::EndDisabled();
    }
    if (ImGui::CollapsingHeader("Appearance")) {
        ImGui::SetNextItemWidth(160);
        ImGui::SliderFloat("Font size", &f.ui.font_size, 11.0f, 24.0f, "%.0f");
        a.cfg.ui.font_size = f.ui.font_size;
    }
    ImGui::EndChild();
    ImGui::Separator();
    if (ImGui::Button(ICON_FA_CHECK " Save & reconnect")) {
        if (a.secret_buf[0]) {
            bool ok = platform::keychain_store(Vault::secret_account(f.storage), trim(a.secret_buf));
            wipe_buf(a.secret_buf, sizeof a.secret_buf);
            if (!ok) a.notify("Keychain not available: set S3VAULT_SECRET_KEY in the environment instead", true);
        }
        f.ui.width = a.cfg.ui.width;
        f.ui.height = a.cfg.ui.height;
        a.cfg = f;
        if (!a.cfg.save(config_path())) a.notify("Cannot write " + config_path(), true);
        else a.notify("Settings saved");
        connect_async(a);
    }
    ImGui::SameLine();
    if (ImGui::Button("Revert")) a.form = a.cfg;
    ImGui::SameLine();
    ImGui::TextDisabled("%s", config_path().c_str());
}

// ---------------------------------------------------------------------------
// modals

// a.modal names the dialog that should be showing. A popup whose id is no longer wanted (changed by a
// background job between frames) is closed here, so no stale modal keeps blocking input.
static bool begin_modal(App& a, const char* id, const char* title) {
    bool want = a.modal == id;
    if (want && !ImGui::IsPopupOpen(title)) ImGui::OpenPopup(title);
    if (!ImGui::IsPopupOpen(title)) return false;
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSizeConstraints(ImVec2(420, 0), ImVec2(900, 700));
    if (!ImGui::BeginPopupModal(title, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return false;
    if (!want) {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return false;
    }
    return true;
}

static void close_modal(App& a) {
    a.modal.clear();
    a.modal_error.clear();
    a.modal_busy = false;
    wipe_buf(a.pw1, sizeof a.pw1);
    wipe_buf(a.pw2, sizeof a.pw2);
    wipe_buf(a.pw_old, sizeof a.pw_old);
    ImGui::CloseCurrentPopup();
}

static void modal_error(App& a) {
    if (!a.modal_error.empty()) ImGui::TextColored(kErr, "%s", a.modal_error.c_str());
    if (a.modal_busy) ImGui::TextDisabled("Working…");
}

static void run_modal_job(App& a, std::function<OpResult()> fn, std::function<void()> on_ok = {}) {
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

static void password_pair(App& a, bool& acceptable) {
    ImGui::SetNextItemWidth(360);
    ImGui::InputText("Password", a.pw1, sizeof a.pw1, ImGuiInputTextFlags_Password);
    ImGui::SameLine();
    if (ImGui::SmallButton("Generate")) {
        std::string g = generate_password();
        snprintf(a.pw1, sizeof a.pw1, "%s", g.c_str());
        snprintf(a.pw2, sizeof a.pw2, "%s", g.c_str());
        glfwSetClipboardString(a.win, g.c_str());
        a.notify("Generated password copied to the clipboard: store it in your password manager");
        wipe(g);
    }
    ImGui::SetNextItemWidth(360);
    ImGui::InputText("Repeat", a.pw2, sizeof a.pw2, ImGuiInputTextFlags_Password);
    acceptable = strength_meter(a.pw1, a.cfg.security.min_length);
    if (a.pw2[0] && strcmp(a.pw1, a.pw2) != 0) {
        ImGui::TextColored(kErr, "Passwords do not match");
        acceptable = false;
    }
    if (!a.pw2[0]) acceptable = false;
}

void draw_modals(App& a) {
    auto v = a.vault;  // may be null before the first connection; dialogs below that need it check

    if (begin_modal(a, "unlock", "Unlock vault")) {
        ImGui::Text(ICON_FA_LOCK " Enter the vault password to work with encrypted files.");
        ImGui::SetNextItemWidth(360);
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        bool enter = ImGui::InputText("##pw", a.pw1, sizeof a.pw1, ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
        const char* how = a.cfg.security.remember == "ask" ? "for this operation only"
                          : a.cfg.security.remember == "session" ? "until you lock or quit"
                          : a.cfg.security.remember == "keychain" ? "in the keychain" : "until idle";
        ImGui::TextDisabled("It will be remembered %s (Settings → Security).", how);
        modal_error(a);
        ImGui::BeginDisabled(a.modal_busy || !a.pw1[0]);
        if (ImGui::Button("Unlock") || (enter && a.pw1[0] && !a.modal_busy)) {
            std::string pw = a.pw1;
            wipe_buf(a.pw1, sizeof a.pw1);
            run_modal_job(a, [v, pw]() mutable { OpResult r = v->unlock(pw); wipe(pw); return r; },
                          [&a] {
                              a.notify("Vault unlocked");
                              if (a.engine) a.engine->request_sync();
                              if (!a.pending_uploads.empty()) a.modal = "upload";  // continue where the user was
                          });
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) close_modal(a);
        if (a.modal != "unlock") close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "create-vault", "Create vault")) {
        ImGui::TextWrapped("No vault exists at %s/%s yet. Choose a password for encrypted files.", a.cfg.storage.bucket.c_str(),
                           a.cfg.storage.prefix.c_str());
        ImGui::TextDisabled("The password protects a random vault key; it cannot be recovered if you lose it.");
        bool okpw = false;
        password_pair(a, okpw);
        modal_error(a);
        ImGui::BeginDisabled(a.modal_busy || !okpw);
        if (ImGui::Button("Create vault")) {
            std::string pw = a.pw1;
            wipe_buf(a.pw1, sizeof a.pw1);
            wipe_buf(a.pw2, sizeof a.pw2);
            run_modal_job(a, [v, pw]() mutable { OpResult r = v->init(pw); wipe(pw); return r; }, [&a] { connect_async(a); });
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::BeginDisabled(a.modal_busy);
        if (ImGui::Button("Create without password")) run_modal_job(a, [v] { return v->init(""); }, [&a] { connect_async(a); });
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Plain files only until you set a password");
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) close_modal(a);
        ImGui::EndDisabled();
        if (a.modal != "create-vault") close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "set-password", "Set vault password") || begin_modal(a, "change-password", "Change vault password")) {
        bool change = a.modal == "change-password";
        if (change) {
            ImGui::SetNextItemWidth(360);
            ImGui::InputText("Current password", a.pw_old, sizeof a.pw_old, ImGuiInputTextFlags_Password);
        }
        bool okpw = false;
        password_pair(a, okpw);
        ImGui::TextDisabled("Only .s3vault/key.gpg is re-encrypted; your files stay as they are.");
        modal_error(a);
        ImGui::BeginDisabled(a.modal_busy || !okpw || (change && !a.pw_old[0]));
        if (ImGui::Button(change ? "Change password" : "Set password")) {
            std::string old = a.pw_old, nw = a.pw1;
            run_modal_job(a, [v, old, nw]() mutable { OpResult r = v->set_password(old, nw); wipe(old); wipe(nw); return r; },
                          [&a] { a.vault_has_key = true; a.notify("Password saved"); });
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) close_modal(a);
        if (a.modal != "set-password" && a.modal != "change-password") close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "upload", "Upload to vault")) {
        ImGui::Text("%zu item(s):", a.pending_uploads.size());
        ImGui::BeginChild("files", ImVec2(560, std::min(160.0f, 22.0f * float(a.pending_uploads.size()) + 8)), ImGuiChildFlags_Borders);
        for (auto& f : a.pending_uploads) ImGui::TextUnformatted(f.c_str());
        ImGui::EndChild();
        ImGui::SetNextItemWidth(360);
        ImGui::InputTextWithHint("Vault folder", "(vault root)", a.text_buf, sizeof a.text_buf);
        ImGui::BeginDisabled(!a.vault_has_key);
        ImGui::Checkbox("Encrypt (gpg, vault key)", &a.upload_encrypt);
        ImGui::EndDisabled();
        if (!a.vault_has_key) ImGui::TextDisabled("Set a vault password to upload encrypted files.");
        if (a.upload_encrypt && !v->unlocked()) ImGui::TextColored(kWarn, ICON_FA_LOCK " The vault is locked; unlock it first.");
        const char* ex[] = {"Overwrite it", "Keep both (rename the upload)", "Skip it"};
        ImGui::SetNextItemWidth(360);
        ImGui::Combo("If a file already exists", &a.upload_on_exists, ex, 3);
        ImGui::BeginDisabled(a.upload_encrypt && !v->unlocked());
        if (ImGui::Button(ICON_FA_UPLOAD " Upload")) {
            std::string dir = trim(a.text_buf);
            while (!dir.empty() && dir.front() == '/') dir.erase(0, 1);
            while (!dir.empty() && dir.back() == '/') dir.pop_back();
            upload_files(a, a.pending_uploads, dir, a.upload_encrypt, a.upload_on_exists);
            a.pending_uploads.clear();
            close_modal(a);
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (a.upload_encrypt && !v->unlocked() && ImGui::Button("Unlock…")) a.modal = "unlock";
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) { a.pending_uploads.clear(); close_modal(a); }
        if (a.modal != "upload" && a.modal != "unlock") close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "new-folder", "New folder")) {
        ImGui::TextDisabled("In /%s", a.current_dir.c_str());
        ImGui::SetNextItemWidth(360);
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        bool enter = ImGui::InputText("Name", a.text_buf, sizeof a.text_buf, ImGuiInputTextFlags_EnterReturnsTrue);
        modal_error(a);
        if ((ImGui::Button("Create") || enter) && a.text_buf[0] && !a.modal_busy) {
            std::string path = join_logical(a.current_dir, trim(a.text_buf));
            run_modal_job(a, [v, path] { OpResult r = v->mkdir(path); if (r.ok) v->refresh(); return r; }, [&a] { a.tree_dirty = true; });
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) close_modal(a);
        if (a.modal != "new-folder") close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "rename", "Rename / move")) {
        ImGui::TextDisabled("From /%s", a.modal_arg.c_str());
        ImGui::SetNextItemWidth(460);
        bool enter = ImGui::InputText("New path", a.text_buf, sizeof a.text_buf, ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::TextDisabled("Moves are server-side copies; nothing is re-uploaded or re-encrypted.");
        modal_error(a);
        if ((ImGui::Button("Rename") || enter) && !a.modal_busy) {
            std::string from = a.modal_arg, to = trim(a.text_buf);
            while (!to.empty() && to.front() == '/') to.erase(0, 1);
            run_modal_job(a, [v, from, to] { return v->rename(from, to); },
                          [&a, to] { a.selected = to; a.tree_dirty = true; if (a.engine) a.engine->request_sync(); });
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) close_modal(a);
        if (a.modal != "rename") close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "delete", "Delete") || begin_modal(a, "delete-multi", "Delete selected")) {
        std::vector<std::string> targets;
        if (a.modal == "delete") targets.push_back(a.modal_arg);
        else targets.assign(a.multi.begin(), a.multi.end());
        ImGui::Text("Move %zu item(s) to the vault trash?", targets.size());
        for (size_t i = 0; i < std::min<size_t>(targets.size(), 8); i++) ImGui::BulletText("/%s", targets[i].c_str());
        if (targets.size() > 8) ImGui::TextDisabled("… and %zu more", targets.size() - 8);
        ImGui::TextDisabled("Tracked copies on other devices go to their desktop trash on their next sync.");
        ImGui::TextDisabled("Trash is kept for %d days (Settings → Sync).", a.cfg.sync.trash_days);
        modal_error(a);
        ImGui::BeginDisabled(a.modal_busy);
        if (ImGui::Button(ICON_FA_TRASH " Delete")) {
            run_modal_job(a, [v, targets] {
                for (auto& t : targets) {
                    OpResult r = v->remove(t);
                    if (!r.ok) return r;
                }
                return OpResult::success();
            }, [&a] { a.multi.clear(); preview_free(a); a.selected.clear(); a.tree_dirty = true; if (a.engine) a.engine->request_sync(); });
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) close_modal(a);
        if (a.modal != "delete" && a.modal != "delete-multi") close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "add-root", "Track a folder")) {
        ImGui::Text("Local folder: %s", a.modal_arg.c_str());
        ImGui::SetNextItemWidth(360);
        ImGui::InputText("Vault path", a.text_buf, sizeof a.text_buf);
        const char* dirs[] = {"two-way", "upload-only", "download-only"};
        ImGui::SetNextItemWidth(360);
        ImGui::Combo("Direction", &a.upload_on_exists, dirs, 3);
        ImGui::BeginDisabled(!a.vault_has_key);
        ImGui::Checkbox("Encrypt new files", &a.upload_encrypt);
        ImGui::EndDisabled();
        modal_error(a);
        if (ImGui::Button("Start syncing")) {
            std::string err;
            std::string rp = trim(a.text_buf);
            int id = a.engine->add_root(a.modal_arg, rp, dirs[a.upload_on_exists], a.upload_encrypt && a.vault_has_key, err);
            if (!id) a.modal_error = err;
            else {
                close_modal(a);
                a.engine->request_sync();
                a.notify("Tracking " + a.modal_arg);
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) close_modal(a);
        if (a.modal != "add-root") close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "remove-root", "Stop tracking")) {
        ImGui::TextWrapped("Stop syncing this folder? Local files and the vault copies are left as they are.");
        if (ImGui::Button("Stop tracking")) {
            a.db.remove_root(atoi(a.modal_arg.c_str()));
            a.tree_dirty = true;
            close_modal(a);
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "resolve", "Resolve conflicts")) {
        std::string how = a.modal_arg;
        const char* desc = how == "keep-both" ? "Keep both: the server version is saved next to yours as \"name (conflict remote …)\"."
                           : how == "keep-local" ? "Overwrite server: your version replaces the server version."
                           : how == "keep-remote" ? "Overwrite local: the server version replaces your file (yours goes to the desktop trash)."
                                                  : "Keep newest: the most recently modified side wins.";
        ImGui::TextWrapped("%s", desc);
        ImGui::Text("%zu file(s):", a.conflict_sel.size());
        auto list = a.db.conflicts();
        ImGui::BeginChild("rl", ImVec2(560, std::min(200.0f, 22.0f * float(a.conflict_sel.size()) + 8)), ImGuiChildFlags_Borders);
        for (auto& c : list)
            if (a.conflict_sel.count(c.id)) ImGui::TextUnformatted(c.rel.c_str());
        ImGui::EndChild();
        modal_error(a);
        ImGui::BeginDisabled(a.modal_busy);
        if (ImGui::Button("Apply")) {
            std::vector<int64_t> ids(a.conflict_sel.begin(), a.conflict_sel.end());
            Resolution r = how == "keep-both" ? Resolution::KeepBoth : how == "keep-local" ? Resolution::KeepLocal
                         : how == "keep-remote" ? Resolution::KeepRemote : Resolution::KeepNewest;
            auto e = a.engine;
            if (!v->unlocked() && a.vault_has_key) { a.modal = "unlock"; }
            else run_modal_job(a, [e, v, ids, r] {
                int fails = 0;
                std::string last;
                for (auto id : ids) {
                    OpResult x = e->resolve(id, r);
                    if (!x.ok) { fails++; last = x.error; }
                }
                v->refresh();
                if (fails) return OpResult::fail(std::to_string(fails) + " could not be resolved: " + last);
                return OpResult::success();
            }, [&a, n = ids.size()] { a.conflict_sel.clear(); a.tree_dirty = true; a.notify("Resolved " + std::to_string(n) + " conflict(s)"); });
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) close_modal(a);
        if (a.modal != "resolve" && a.modal != "unlock") close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "compare", "Compare versions")) {
        // Text comparison of both sides, loaded on demand and bounded like previews.
        static int64_t loaded_id = 0;
        static std::string local_txt, remote_txt, err;
        static bool loading = false;
        int64_t id = atoll(a.modal_arg.c_str());
        ConflictRow c{};
        bool have = a.db.conflict(id, c);
        if (have && loaded_id != id && !loading) {
            loading = true;
            loaded_id = id;
            wipe(local_txt); wipe(remote_txt); err.clear();
            std::string root_path;
            for (auto& r : a.db.roots()) if (r.id == c.root_id) root_path = r.local_path;
            size_t cap = size_t(a.cfg.preview.text_max_mb) << 20;
            a.run_job([&a, v, c, root_path, cap] {
                std::string l, r, e;
                if (c.local_exists && !read_file(root_path + "/" + c.rel, l, cap)) e = "local file too large or unreadable";
                if (c.remote_exists) {
                    OpResult o = v->download_to_memory(c.remote_key, r, cap);
                    if (!o.ok) e = o.error;
                }
                a.post([l, r, e]() mutable { local_txt = std::move(l); remote_txt = std::move(r); err = e; loading = false; });
            });
        }
        ImGui::Text("%s", have ? c.rel.c_str() : "(resolved)");
        if (loading) ImGui::TextDisabled("Loading…");
        if (!err.empty()) ImGui::TextColored(kErr, "%s", err.c_str());
        bool text = preview_kind(c.rel) == PreviewKind::Text && utf8_valid(local_txt) && utf8_valid(remote_txt);
        if (ImGui::BeginTable("cmp", 2, ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable, ImVec2(860, 420))) {
            ImGui::TableSetupColumn("This device", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Server", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            ImGui::TableNextRow();
            for (int side = 0; side < 2; side++) {
                ImGui::TableNextColumn();
                const std::string& t = side == 0 ? local_txt : remote_txt;
                ImGui::BeginChild(side == 0 ? "l" : "r", ImVec2(0, 380));
                if ((side == 0 ? !c.local_exists : !c.remote_exists)) ImGui::TextDisabled("(deleted)");
                else if (text) ImGui::TextUnformatted(t.data(), t.data() + t.size());
                else ImGui::TextDisabled("%s · SHA-256 %s", human_size(t.size()).c_str(), sha256_hex(t).substr(0, 16).c_str());
                ImGui::EndChild();
            }
            ImGui::EndTable();
        }
        if (ImGui::Button("Close")) {
            wipe(local_txt);
            wipe(remote_txt);
            loaded_id = 0;
            close_modal(a);
        }
        ImGui::EndPopup();
    }

    if (begin_modal(a, "edit-changed", "Save changes?")) {
        EditSession s;
        bool have = a.edits->get(a.edit_prompt_id, s);
        ImGui::TextWrapped("%s was changed in the editor. Save it back to the vault?", have ? s.logical.c_str() : "The file");
        modal_error(a);
        ImGui::BeginDisabled(a.modal_busy || !have);
        auto em = a.edits;
        int id = a.edit_prompt_id;
        if (ImGui::Button(ICON_FA_CLOUD_ARROW_UP " Save back")) {
            a.edits->clear_prompt(id);
            a.modal_busy = true;
            a.run_job([&a, em, id] {
                OpResult r = em->save_back(id);
                a.post([&a, r, id] {
                    a.modal_busy = false;
                    if (r.ok) { a.modal.clear(); a.notify("Saved to the vault"); a.tree_dirty = true; if (a.engine) a.engine->request_sync(); }
                    else if (r.precondition_failed) { a.edit_prompt_id = id; a.modal = "edit-conflict"; }
                    else a.modal_error = r.error;
                });
            });
        }
        ImGui::SameLine();
        if (ImGui::Button("Keep editing")) { a.edits->clear_prompt(id); close_modal(a); }
        ImGui::SameLine();
        if (ImGui::Button("Discard changes")) { a.edits->discard(id); close_modal(a); }
        ImGui::EndDisabled();
        if (a.modal != "edit-changed") close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "edit-conflict", "Changed on the server")) {
        EditSession s;
        a.edits->get(a.edit_prompt_id, s);
        ImGui::TextWrapped("%s was changed on the server since you opened it.", s.logical.c_str());
        modal_error(a);
        auto em = a.edits;
        int id = a.edit_prompt_id;
        auto after = [&a](const char* msg) { return [&a, msg] { a.notify(msg); a.tree_dirty = true; if (a.engine) a.engine->request_sync(); }; };
        ImGui::BeginDisabled(a.modal_busy);
        if (ImGui::Button("Keep both")) run_modal_job(a, [em, id] { return em->save_as_copy(id); }, after("Saved your version as a copy"));
        ImGui::SameLine();
        if (ImGui::Button("Overwrite server")) run_modal_job(a, [em, id] { return em->save_back(id, true); }, after("Saved over the server version"));
        ImGui::SameLine();
        if (ImGui::Button("Reload server version")) run_modal_job(a, [em, id] { return em->reload(id); }, after("Reloaded; your edits were discarded"));
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) close_modal(a);
        ImGui::EndDisabled();
        if (a.modal != "edit-conflict") close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "edit-discard", "Discard changes?")) {
        ImGui::Text("Throw away the unsaved changes?");
        if (ImGui::Button("Discard")) { a.edits->discard(a.edit_prompt_id); close_modal(a); }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "force-edit", "Open as text?")) {
        ImGui::TextWrapped("%s does not look like a text file. Open it in the text editor anyway? Saving binary files from a text editor can damage them.",
                           a.modal_arg.c_str());
        if (ImGui::Button("Open anyway")) {
            const Node* n = find_node(a.tree.get(), a.modal_arg);
            close_modal(a);
            if (n && !n->dir) open_in_editor(a, n->entry, true);
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "open-warning", "Open with another app")) {
        ImGui::TextWrapped("The decrypted copy is written to %s and wiped when you lock or quit. The other app may keep its own copies "
                           "(recent files, thumbnails, autosave), which s3vault cannot remove.",
                           platform::session_tmp_in_ram() ? "RAM (tmpfs)" : "a temporary folder");
        if (ImGui::Button("Open")) {
            a.open_warning_shown = true;
            std::string target = a.modal_arg;
            close_modal(a);
            if (const Node* n = find_node(a.tree.get(), target); n && !n->dir) open_externally(a, n->entry);
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) close_modal(a);
        ImGui::EndPopup();
    }

    if (begin_modal(a, "lock-unsaved", "Unsaved edits") || begin_modal(a, "quit-unsaved", "Unsaved edits")) {
        bool quit = a.modal == "quit-unsaved";
        ImGui::TextWrapped("Some files open in the editor have unsaved changes.");
        modal_error(a);
        auto em = a.edits;
        ImGui::BeginDisabled(a.modal_busy);
        if (ImGui::Button("Save all")) {
            run_modal_job(a, [em] {
                for (auto& s : em->sessions())
                    if (s.changed) {
                        OpResult r = em->save_back(s.id);
                        if (!r.ok) return OpResult::fail(s.logical + ": " + r.error);
                    }
                return OpResult::success();
            }, [&a, quit] { if (quit) a.quit_confirmed = true; else lock_vault(a, true); });
        }
        ImGui::SameLine();
        if (ImGui::Button("Discard all")) {
            a.edits->close_all();
            close_modal(a);
            if (quit) a.quit_confirmed = true;
            else lock_vault(a, true);
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) { a.quit_requested = false; close_modal(a); }
        ImGui::EndDisabled();
        if (a.modal != "lock-unsaved" && a.modal != "quit-unsaved") close_modal(a);
        ImGui::EndPopup();
    }
}

}  // namespace s3v::ui
