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

#include <cstring>

namespace s3v::ui {


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
    float top = page_header("Editor", "Decrypted text stays in memory; nothing is written to disk");
    ImGui::SetCursorPos(ImVec2(16, top + 8));
    ImGui::BeginChild("##editor", ImVec2(ImGui::GetWindowWidth() - 32, ImGui::GetWindowHeight() - top - 16), ImGuiChildFlags_None,
                      ImGuiWindowFlags_NoScrollbar);
    if (ids.empty()) {
        empty_state(ICON_FA_PEN_TO_SQUARE, "No Files Open", "Select a text file and choose Edit (Ctrl+E).");
    } else if (ImGui::BeginTabBar("docs", ImGuiTabBarFlags_AutoSelectNewTabs | ImGuiTabBarFlags_FittingPolicyScroll)) {
        for (int id : ids) {
            EditDoc* d = em->doc(id);
            if (!d) continue;
            bool open = true;
            ImGuiTabItemFlags f = (d->dirty() ? ImGuiTabItemFlags_UnsavedDocument : 0) |
                                  (a.edit_focus == id ? ImGuiTabItemFlags_SetSelected : 0);
            std::string label = std::string(type_icon(d->logical, false)) + "  " + path_basename(d->logical) + "###doc" + std::to_string(id);
            bool visible = ImGui::BeginTabItem(label.c_str(), &open, f);
            if (!open) {
                if (d->dirty()) { a.edit_close_id = id; a.modal = "edit-close"; }
                else em->close(id);
            }
            if (!visible) continue;
            ImGui::Dummy(ImVec2(0, 4));
            bool save = button(ICON_FA_CLOUD_ARROW_UP "  Save", d->dirty() ? Btn::Primary : Btn::Secondary, ImVec2(0, 0), d->dirty());
            tip("Ctrl+S — saves back to the vault (encrypted again if the file is)");
            ImGui::SameLine();
            if (button("Revert", Btn::Secondary, ImVec2(0, 0), d->dirty())) d->text = d->saved;
            ImGui::SameLine();
            if (button("Reload", Btn::Secondary)) reload_doc(a, id);
            tip("Load the server's current version");
            ImGui::SameLine();
            if (button("Close", Btn::Secondary)) {
                if (d->dirty()) { a.edit_close_id = id; a.modal = "edit-close"; }
                else { em->close(id); ImGui::EndTabItem(); continue; }
            }
            size_t lines = std::count(d->text.begin(), d->text.end(), '\n') + 1;
            ImGui::SameLine(0, 16);
            ImGui::AlignTextToFramePadding();
            status_text(d->dirty() ? P.orange : P.green, d->dirty() ? "Edited" : "Saved");
            ImGui::SameLine(0, 12);
            small_dim("/%s%s · %zu lines · %s", d->logical.c_str(), ends_with(d->key, ".gpg") ? " · encrypted" : "", lines, human_size(d->text.size()).c_str());
            if (!d->error.empty()) ImGui::TextColored(P.red, "%s", d->error.c_str());
            if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_S) && d->dirty()) save = true;
            ImGui::Dummy(ImVec2(0, 2));
            ImGui::PushStyleColor(ImGuiCol_FrameBg, P.card);
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(12, 10));
            ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1);
            if (g_mono) ImGui::PushFont(g_mono, ImGui::GetStyle().FontSizeBase * 0.93f);
            ImGui::InputTextMultiline("##text", &d->text, ImVec2(-1, -1), ImGuiInputTextFlags_AllowTabInput);
            if (g_mono) ImGui::PopFont();
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor();
            if (save) save_doc(a, id, false);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::EndChild();
    a.edit_focus = 0;

    // Sheets for this view
    if (sheet_begin(a.modal, "edit-close", 420)) {
        EditDoc* d = em->doc(a.edit_close_id);
        std::string t = "Save Changes to \"" + (d ? path_basename(d->logical) : std::string("the file")) + "\"?";
        sheet_title(ICON_FA_PEN_TO_SQUARE, P.orange, t.c_str(), "Your changes will be lost if you don't save them.");
        int id = a.edit_close_id;
        int extra = 0;
        int r = sheet_buttons("Save", "Cancel", true, false, "Don't Save", &extra);
        if (extra) { em->close(id); sheet_close(a.modal); }
        else if (r == 1) { save_doc(a, id, false); sheet_close(a.modal); }
        else if (r == 2) sheet_close(a.modal);
        sheet_end();
    }
    if (sheet_begin(a.modal, "edit-conflict", 480)) {
        EditDoc* d = em->doc(a.edit_close_id);
        std::string sub = (d ? "/" + d->logical : std::string("The file")) + " was changed on another device since you opened it.";
        sheet_title(ICON_FA_CODE_MERGE, P.orange, "Someone Else Changed This File", sub.c_str());
        int id = a.edit_close_id;
        int extra = 0;
        int r = sheet_buttons("Keep Both", "Cancel", d != nullptr, false, "Replace Theirs", &extra);
        if (ImGui::IsItemHovered()) {}
        if (r == 1 && d) {
            std::string text = d->text;
            a.run_job([&a, em, id, text]() mutable {
                OpResult x = em->save_as_copy(id, text);
                wipe(text);
                a.post([&a, em, id, x] {
                    if (x.ok) { em->close(id); a.notify("Saved your version as a copy"); a.tree_dirty = true; }
                    else a.notify(x.error, true);
                });
            });
            sheet_close(a.modal);
        } else if (extra) {
            save_doc(a, id, true);
            sheet_close(a.modal);
        } else if (r == 2) {
            sheet_close(a.modal);
        }
        if (button("Discard Mine and Reload Theirs", Btn::Plain)) { reload_doc(a, id); sheet_close(a.modal); }
        sheet_end();
    }
}

}  // namespace s3v::ui
