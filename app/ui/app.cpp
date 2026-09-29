// App lifecycle, background jobs, the main frame (toolbar + tabs) and the vault tree model.
#include "app.h"

#include <GLFW/glfw3.h>

#include <algorithm>
#include <cstring>

#include "IconsFontAwesome6.h"
#include "imgui.h"
#include "platform.h"
#include "util/strings.h"

namespace s3v::ui {

// ---------------------------------------------------------------------------
// jobs

void App::run_job(std::function<void()> fn) {
    busy++;
    jobs.emplace_back([this, fn = std::move(fn)] {
        fn();
        busy--;
        glfwPostEmptyEvent();
    });
}

void App::post(std::function<void()> fn) {
    {
        std::lock_guard<std::mutex> lk(ui_mu);
        ui_queue.push_back(std::move(fn));
    }
    glfwPostEmptyEvent();
}

void App::drain_ui_queue() {
    std::deque<std::function<void()>> q;
    {
        std::lock_guard<std::mutex> lk(ui_mu);
        q.swap(ui_queue);
    }
    for (auto& f : q) f();
    // Reap finished job threads.
    if (busy == 0 && !jobs.empty()) join_jobs();
}

void App::join_jobs() {
    for (auto& t : jobs)
        if (t.joinable()) t.join();
    jobs.clear();
}

void App::notify(const std::string& t, bool error) {
    toast.text = t;
    toast.error = error;
    toast.until = glfwGetTime() + (error ? 6.0 : 3.0);
}

// ---------------------------------------------------------------------------
// lifecycle

static bool storage_configured(const Config& c) {
    return !c.storage.bucket.empty() && !c.storage.access_key_id.empty() &&
           (c.storage.provider != "r2" || !c.storage.account_id.empty() || c.storage.endpoint != "auto");
}

void connect_async(App& a) {
    if (a.engine) a.engine->stop();
    a.join_jobs();  // nothing may still hold the old vault
    preview_free(a);
    if (a.edits) a.edits->close_all();
    if (!storage_configured(a.cfg)) {
        a.conn = App::Conn::Unconfigured;
        a.want_tab = 5;
        return;
    }
    a.conn = App::Conn::Connecting;
    a.vault = std::make_unique<Vault>(a.cfg, a.db);
    a.engine = std::make_unique<Engine>(a.cfg, a.db, *a.vault);
    a.edits = std::make_unique<EditManager>(a.cfg, *a.vault);
    a.engine->on_synced = [&a] { a.post([&a] { a.tree_dirty = true; }); };
    Vault* v = a.vault.get();
    a.run_job([&a, v] {
        std::string err;
        if (!v->connect(err)) {
            a.post([&a, err] { a.conn = App::Conn::Error; a.conn_error = err; a.want_tab = 5; });
            return;
        }
        bool exists = false;
        OpResult r = v->load_info(exists);
        if (!r.ok) {
            a.post([&a, e = r.error] { a.conn = App::Conn::Error; a.conn_error = e; });
            return;
        }
        if (!exists) {
            a.post([&a] { a.conn = App::Conn::NoVault; a.modal = "create-vault"; });
            return;
        }
        bool key = v->has_key();
        if (key) v->try_unlock_from_keychain();
        v->refresh();
        a.post([&a, key] {
            a.vault_has_key = key;
            a.conn = App::Conn::Ready;
            a.tree_dirty = true;
            a.upload_encrypt = key;
            if (key && !a.vault->unlocked()) a.modal = "unlock";
            a.engine->start();
        });
    });
}

void app_init(App& a) {
    a.cfg.load(config_path());
    std::string err;
    if (!a.db.open(data_dir() + "/index.db", &err)) a.notify("index: " + err, true);
    a.form = a.cfg;
    int n = platform::cleanup_stale_tmp();
    if (n) a.notify("Removed " + std::to_string(n) + " leftover temporary folder(s) from a previous session");
    connect_async(a);
}

void lock_vault(App& a, bool manual) {
    preview_free(a);
    if (a.edits) {
        // Unsaved edits survive an automatic lock (their plaintext stays in the RAM tmp dir) so nothing
        // is lost; saved ones are closed and wiped.
        for (auto& s : a.edits->sessions())
            if (!s.changed || manual) a.edits->discard(s.id);
    }
    if (a.vault) {
        if (manual) a.vault->lock();
        else a.vault->keys().lock();
    }
    if (!a.edits || a.edits->sessions().empty()) platform::wipe_session_tmp();
    a.notify(manual ? "Vault locked" : "Vault locked after inactivity");
}

void app_shutdown(App& a) {
    if (a.engine) a.engine->stop();
    preview_free(a);
    if (a.edits) a.edits->close_all();
    a.join_jobs();
    platform::wipe_session_tmp();
    a.cfg.save(config_path());
}

// ---------------------------------------------------------------------------
// tree model

static Node* child_dir(Node* parent, const std::string& name, const std::string& logical) {
    for (auto& k : parent->kids)
        if (k->dir && k->name == name) return k.get();
    auto n = std::make_unique<Node>();
    n->name = name;
    n->logical = logical;
    n->dir = true;
    parent->kids.push_back(std::move(n));
    return parent->kids.back().get();
}

static void finish(Node* n, int col, bool desc) {
    for (auto& k : n->kids) {
        if (k->dir) finish(k.get(), col, desc);
        n->size += k->size;
        n->mtime = std::max(n->mtime, k->mtime);
    }
    std::sort(n->kids.begin(), n->kids.end(), [&](const std::unique_ptr<Node>& x, const std::unique_ptr<Node>& y) {
        if (x->dir != y->dir) return x->dir;  // folders first, whatever the direction
        int c = 0;
        switch (col) {
            case 1: c = strcmp(file_type_label(x->name), file_type_label(y->name)); break;
            case 2: c = x->size < y->size ? -1 : x->size > y->size ? 1 : 0; break;
            case 3: c = x->mtime < y->mtime ? -1 : x->mtime > y->mtime ? 1 : 0; break;
            case 4: c = x->status.compare(y->status); break;
        }
        if (c == 0) c = strcasecmp(x->name.c_str(), y->name.c_str());
        return desc ? c > 0 : c < 0;
    });
}

static bool passes_filter(App& a, const RemoteEntry& e) {
    if (a.filter[0]) {
        std::string f = to_lower(a.filter);
        if (to_lower(e.logical).find(f) == std::string::npos) return false;
    }
    switch (a.type_filter) {
        case 1: return preview_kind(e.logical) == PreviewKind::Text;
        case 2: return preview_kind(e.logical) == PreviewKind::Image;
        case 3: return preview_kind(e.logical) == PreviewKind::Pdf;
        case 4: return e.encrypted;
    }
    return true;
}

// Sync status per logical path from the tracked roots' base rows and open conflicts.
static void compute_status(App& a, const std::vector<RemoteEntry>& entries) {
    a.status_by_logical.clear();
    auto roots = a.db.roots();
    std::map<int, std::map<std::string, FileRow>> files;
    for (auto& r : roots) files[r.id] = a.db.files(r.id);
    std::set<std::string> conflicted;
    for (auto& c : a.db.conflicts())
        for (auto& r : roots)
            if (r.id == c.root_id) conflicted.insert(r.remote_prefix.empty() ? c.rel : r.remote_prefix + "/" + c.rel);
    for (auto& e : entries) {
        if (e.dir_marker) continue;
        std::string st = "Cloud only";
        for (auto& r : roots) {
            std::string pfx = r.remote_prefix.empty() ? "" : r.remote_prefix + "/";
            if (!starts_with(e.logical, pfx)) continue;
            std::string rel = e.logical.substr(pfx.size());
            auto& fm = files[r.id];
            auto it = fm.find(rel);
            st = r.paused ? "Paused" : it != fm.end() && it->second.base_etag == e.etag && it->second.l_hash == it->second.base_hash ? "Synced" : "Pending";
            break;
        }
        if (conflicted.count(e.logical)) st = "Conflict";
        a.status_by_logical[e.logical] = st;
    }
}

void rebuild_tree(App& a) {
    a.tree_dirty = false;
    auto root = std::make_unique<Node>();
    root->dir = true;
    if (!a.vault) {
        a.tree = std::move(root);
        return;
    }
    auto entries = a.vault->cached_entries();
    a.db.remote_cache(&a.listed_at);
    compute_status(a, entries);
    for (auto& e : entries) {
        if (!e.dir_marker && !passes_filter(a, e)) continue;
        auto parts = split(e.logical, '/');
        Node* cur = root.get();
        std::string path;
        size_t ndirs = e.dir_marker ? parts.size() : parts.size() - 1;
        for (size_t i = 0; i < ndirs; i++) {
            path = path.empty() ? parts[i] : path + "/" + parts[i];
            cur = child_dir(cur, parts[i], path);
        }
        if (e.dir_marker) {
            if (a.filter[0] || a.type_filter) continue;
            cur->mtime = std::max(cur->mtime, e.mtime);
            continue;
        }
        auto n = std::make_unique<Node>();
        n->name = parts.back();
        n->logical = e.logical;
        n->entry = e;
        n->size = e.size;
        n->mtime = e.mtime;
        n->status = a.status_by_logical[e.logical];
        cur->kids.push_back(std::move(n));
    }
    // With a filter active, drop folders left empty.
    std::function<bool(Node*)> prune = [&](Node* n) {
        n->kids.erase(std::remove_if(n->kids.begin(), n->kids.end(),
                                     [&](std::unique_ptr<Node>& k) { return k->dir && !prune(k.get()) && (a.filter[0] || a.type_filter); }),
                      n->kids.end());
        return !n->kids.empty();
    };
    prune(root.get());
    finish(root.get(), a.sort_col, a.sort_desc);
    a.tree = std::move(root);
}

// ---------------------------------------------------------------------------
// frame

static void toolbar(App& a) {
    using C = App::Conn;
    C c = a.conn;
    ImGui::AlignTextToFramePadding();
    const std::string& bucket = a.cfg.storage.bucket;
    switch (c) {
        case C::Unconfigured: ImGui::TextColored({0.9f, 0.7f, 0.2f, 1}, ICON_FA_GEAR "  Storage not configured"); break;
        case C::Connecting: ImGui::TextDisabled(ICON_FA_CLOUD "  Connecting to %s…", bucket.c_str()); break;
        case C::Error: ImGui::TextColored({0.95f, 0.35f, 0.3f, 1}, ICON_FA_TRIANGLE_EXCLAMATION "  %s", a.conn_error.c_str()); break;
        case C::NoVault: ImGui::TextColored({0.9f, 0.7f, 0.2f, 1}, ICON_FA_CLOUD "  No vault at %s/%s", bucket.c_str(), a.cfg.storage.prefix.c_str()); break;
        case C::Ready: ImGui::Text(ICON_FA_CLOUD "  %s/%s", bucket.c_str(), a.vault->prefix().c_str()); break;
    }
    if (c == C::Ready) {
        ImGui::SameLine();
        if (a.vault_has_key) {
            bool un = a.vault->unlocked();
            if (un) {
                int64_t left = a.vault->keys().seconds_left();
                if (ImGui::Button(ICON_FA_UNLOCK " Lock")) {
                    if (a.edits && a.edits->any_unsaved()) a.modal = "lock-unsaved";
                    else lock_vault(a, true);
                }
                if (left >= 0 && ImGui::IsItemHovered())
                    ImGui::SetTooltip("Locks automatically after %lld min of inactivity", static_cast<long long>(left / 60 + 1));
            } else if (ImGui::Button(ICON_FA_LOCK " Unlock")) {
                a.modal = "unlock";
            }
        } else if (ImGui::Button(ICON_FA_KEY " Set password")) {
            a.modal = "set-password";
        }
        ImGui::SameLine();
        bool syncing = a.engine && a.engine->syncing();
        ImGui::BeginDisabled(syncing);
        if (ImGui::Button(syncing ? ICON_FA_ROTATE " Syncing…" : ICON_FA_ARROWS_ROTATE " Sync now")) a.engine->request_sync();
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (a.engine && a.engine->last_sync())
            ImGui::TextDisabled("Last sync %s · %s", format_local_time(a.engine->last_sync()).c_str(), a.engine->last_summary().c_str());
    } else if (c == C::Error || c == C::NoVault) {
        ImGui::SameLine();
        if (ImGui::Button("Retry")) connect_async(a);
    }
}

void app_frame(App& a) {
    a.drain_ui_queue();
    if (a.tree_dirty) rebuild_tree(a);

    // Idle lock: user input counts as activity.
    if (a.vault && a.vault->unlocked() && a.had_input) {
        a.vault->keys().get();
        a.had_input = false;
    }
    if (a.vault && a.vault->keys().tick()) lock_vault(a, false);
    preview_tick(a);
    if (a.edits) {
        a.edits->poll();
        if (a.modal.empty())
            for (auto& s : a.edits->sessions())
                if (s.prompt) {
                    a.edit_prompt_id = s.id;
                    a.modal = "edit-changed";
                    break;
                }
    }

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##main", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                     ImGuiWindowFlags_NoBringToFrontOnFocus);
    toolbar(a);
    ImGui::Separator();

    size_t nconf = a.db.conflicts().size();
    size_t nedit = a.edits ? a.edits->sessions().size() : 0;
    size_t nxfer = a.engine ? a.engine->transfers().size() : 0;
    if (ImGui::BeginTabBar("tabs")) {
        auto tab = [&](int id, const std::string& label) {
            ImGuiTabItemFlags f = a.want_tab == id ? ImGuiTabItemFlags_SetSelected : 0;
            bool open = ImGui::BeginTabItem(label.c_str(), nullptr, f);
            if (open) a.tab = id;
            return open;
        };
        if (tab(0, ICON_FA_FOLDER_OPEN " Vault###vault")) { draw_vault_tab(a); ImGui::EndTabItem(); }
        if (tab(1, ICON_FA_HARD_DRIVE " Tracked folders###folders")) { draw_folders_tab(a); ImGui::EndTabItem(); }
        std::string cl = std::string(ICON_FA_TRIANGLE_EXCLAMATION " Conflicts") + (nconf ? " (" + std::to_string(nconf) + ")" : "") + "###conflicts";
        if (nconf) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.75f, 0.3f, 1));
        bool ct = tab(2, cl);
        if (nconf) ImGui::PopStyleColor();
        if (ct) { draw_conflicts_tab(a); ImGui::EndTabItem(); }
        std::string tl = std::string(ICON_FA_CLOUD_ARROW_UP " Transfers") + (nxfer ? " (" + std::to_string(nxfer) + ")" : "") + "###transfers";
        if (tab(3, tl)) { draw_transfers_tab(a); ImGui::EndTabItem(); }
        std::string el = std::string(ICON_FA_PEN_TO_SQUARE " Edits") + (nedit ? " (" + std::to_string(nedit) + ")" : "") + "###edits";
        if (tab(4, el)) { draw_edits_tab(a); ImGui::EndTabItem(); }
        if (tab(5, ICON_FA_GEAR " Settings###settings")) { draw_settings_tab(a); ImGui::EndTabItem(); }
        ImGui::EndTabBar();
    }
    a.want_tab = -1;
    ImGui::End();

    draw_modals(a);

    // Toast
    if (!a.toast.text.empty() && glfwGetTime() < a.toast.until) {
        ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + vp->WorkSize.x - 12, vp->WorkPos.y + vp->WorkSize.y - 12), 0, ImVec2(1, 1));
        ImGui::SetNextWindowBgAlpha(0.92f);
        ImGui::Begin("##toast", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoFocusOnAppearing |
                         ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoInputs);
        if (a.toast.error) ImGui::TextColored({1, 0.45f, 0.4f, 1}, ICON_FA_TRIANGLE_EXCLAMATION " %s", a.toast.text.c_str());
        else ImGui::Text(ICON_FA_CIRCLE_CHECK " %s", a.toast.text.c_str());
        ImGui::End();
    }
}

}  // namespace s3v::ui
