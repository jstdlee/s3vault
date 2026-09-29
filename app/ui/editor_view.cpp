// Built-in text editor (Editor tab). Decrypted text lives only in this process's memory: it is never
// written to disk and never handed to another program. Saving re-encrypts and uploads with If-Match.
#include <GLFW/glfw3.h>

#include <algorithm>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "imgui.h"
#include "misc/cpp/imgui_stdlib.h"
#include "util/secure.h"
#include "util/strings.h"

namespace s3v::ui {

static const ImVec4 kWarn(1.0f, 0.75f, 0.3f, 1), kErr(1.0f, 0.45f, 0.4f, 1);

static void save_doc(App& a, int id, bool force) {
    auto em = a.edits;
    EditDoc* d = em->doc(id);
    if (!d) return;
    std::string text = d->text;  // snapshot; typing can continue while it uploads
    a.run_job([&a, em, id, text, force]() mutable {
        OpResult r = em->save(id, text, force);
        if (r.ok) em->apply_saved(id, text, r.etag);
        wipe(text);
        a.post([&a, em, id, r] {
            EditDoc* d = em->doc(id);
            if (r.ok) {
                a.notify("Saved to the vault");
                a.tree_dirty = true;
                if (a.engine) a.engine->request_sync();
            } else if (r.precondition_failed) {
                if (d) d->conflict = true;
                a.edit_close_id = id;
                a.modal = "edit-conflict";
            } else {
                if (d) d->error = r.error;
                a.notify(r.error, true);
            }
        });
    });
}

static void reload_doc(App& a, int id) {
    auto em = a.edits;
    a.run_job([&a, em, id] {
        std::string text, etag;
        OpResult r = em->reload(id, text, etag);
        a.post([&a, em, id, r, text = std::move(text), etag]() mutable {
            if (!r.ok) { a.notify(r.error, true); wipe(text); return; }
            if (EditDoc* d = em->doc(id)) {
                wipe(d->text);
                d->text = text;
                em->apply_saved(id, text, etag);
            }
            wipe(text);
            a.notify("Reloaded the server version");
        });
    });
}

void save_all_docs(App& a) {
    if (!a.edits) return;
    for (int id : a.edits->ids())
        if (EditDoc* d = a.edits->doc(id); d && d->dirty()) save_doc(a, id, false);
}

void draw_edits_tab(App& a) {
    auto em = a.edits;
    if (!em) return;
    auto ids = em->ids();
    if (ids.empty()) {
        ImGui::Spacing();
        ImGui::TextDisabled("No files open. Use Edit on a text file in the Vault tab.");
        ImGui::TextDisabled("The editor is built in: decrypted text stays in memory and is never written to disk.");
    } else if (ImGui::BeginTabBar("docs", ImGuiTabBarFlags_AutoSelectNewTabs | ImGuiTabBarFlags_FittingPolicyScroll)) {
        for (int id : ids) {
            EditDoc* d = em->doc(id);
            if (!d) continue;
            bool open = true;
            ImGuiTabItemFlags f = (d->dirty() ? ImGuiTabItemFlags_UnsavedDocument : 0) |
                                  (a.edit_focus == id ? ImGuiTabItemFlags_SetSelected : 0);
            std::string label = path_basename(d->logical) + "###doc" + std::to_string(id);
            bool visible = ImGui::BeginTabItem(label.c_str(), &open, f);
            if (!open) {  // tab's close button
                if (d->dirty()) { a.edit_close_id = id; a.modal = "edit-close"; }
                else em->close(id);
            }
            if (!visible) continue;
            ImGui::TextDisabled("/%s%s", d->logical.c_str(), ends_with(d->key, ".gpg") ? "  " ICON_FA_LOCK " encrypted" : "");
            ImGui::SameLine();
            if (d->dirty()) ImGui::TextColored(kWarn, ICON_FA_PEN " unsaved");
            else ImGui::TextDisabled(ICON_FA_CHECK " saved");
            if (!d->error.empty()) { ImGui::SameLine(); ImGui::TextColored(kErr, "%s", d->error.c_str()); }
            ImGui::BeginDisabled(!d->dirty());
            bool save = ImGui::Button(ICON_FA_CLOUD_ARROW_UP " Save to vault");
            ImGui::EndDisabled();
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) ImGui::SetTooltip("Ctrl+S");
            ImGui::SameLine();
            ImGui::BeginDisabled(!d->dirty());
            if (ImGui::Button("Revert")) d->text = d->saved;
            ImGui::EndDisabled();
            ImGui::SameLine();
            if (ImGui::Button("Reload from server")) reload_doc(a, id);
            ImGui::SameLine();
            if (ImGui::Button(ICON_FA_XMARK " Close")) {
                if (d->dirty()) { a.edit_close_id = id; a.modal = "edit-close"; }
                else { em->close(id); ImGui::EndTabItem(); continue; }
            }
            size_t lines = std::count(d->text.begin(), d->text.end(), '\n') + 1;
            ImGui::SameLine();
            ImGui::TextDisabled("%zu lines · %s", lines, human_size(d->text.size()).c_str());
            if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_S) && d->dirty()) save = true;
            ImGui::InputTextMultiline("##text", &d->text, ImVec2(-1, -1), ImGuiInputTextFlags_AllowTabInput);
            if (save) save_doc(a, id, false);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    a.edit_focus = 0;

    // Dialogs for this tab
    auto begin = [&](const char* id, const char* title) {
        bool want = a.modal == id;
        if (want && !ImGui::IsPopupOpen(title)) ImGui::OpenPopup(title);
        if (!ImGui::IsPopupOpen(title)) return false;
        ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
        if (!ImGui::BeginPopupModal(title, nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return false;
        if (!want) { ImGui::CloseCurrentPopup(); ImGui::EndPopup(); return false; }
        return true;
    };
    auto done = [&] { a.modal.clear(); ImGui::CloseCurrentPopup(); };
    if (begin("edit-close", "Unsaved changes")) {
        EditDoc* d = em->doc(a.edit_close_id);
        ImGui::Text("Save changes to %s before closing?", d ? path_basename(d->logical).c_str() : "the file");
        int id = a.edit_close_id;
        if (ImGui::Button("Save")) { save_doc(a, id, false); done(); }
        ImGui::SameLine();
        if (ImGui::Button("Discard")) { em->close(id); done(); }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) done();
        ImGui::EndPopup();
    }
    if (begin("edit-conflict", "Changed on the server")) {
        EditDoc* d = em->doc(a.edit_close_id);
        ImGui::TextWrapped("%s was changed on the server since you opened it.", d ? d->logical.c_str() : "The file");
        int id = a.edit_close_id;
        if (ImGui::Button("Keep both")) {
            if (d) {
                std::string text = d->text;
                a.run_job([&a, em, id, text]() mutable {
                    OpResult r = em->save_as_copy(id, text);
                    wipe(text);
                    a.post([&a, em, id, r] {
                        if (r.ok) { em->close(id); a.notify("Saved your version as a copy"); a.tree_dirty = true; }
                        else a.notify(r.error, true);
                    });
                });
            }
            done();
        }
        ImGui::SameLine();
        if (ImGui::Button("Overwrite server")) { save_doc(a, id, true); done(); }
        ImGui::SameLine();
        if (ImGui::Button("Reload server version")) { reload_doc(a, id); done(); }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) done();
        ImGui::EndPopup();
    }
}

}  // namespace s3v::ui
