// App lifecycle, background jobs, the main frame (toolbar + tabs) and the vault tree model.
#include "app.h"

#include <GLFW/glfw3.h>

#include <algorithm>
#include <cstring>

#include "IconsFontAwesome6.h"
#include "imgui.h"
#include "imgui_internal.h"
#include "platform.h"
#include "util/fs.h"
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

// Drops the current session without waiting: its engine stops (aborting transfers) on a worker thread,
// and it is destroyed once the last background job holding it finishes.
static void retire_session(App& a) {
    preview_free(a);
    if (a.edits) a.edits->close_all();
    auto old = a.sess;
    a.vault.reset();
    a.engine.reset();
    a.edits.reset();
    a.sess.reset();
    if (old) std::thread([old]() mutable { if (old->engine) old->engine->stop(); old.reset(); }).detach();
}

void connect_async(App& a) {
    retire_session(a);
    a.tree.reset();
    a.status_by_logical.clear();
    a.selected.clear();
    a.multi.clear();
    if (!storage_configured(a.cfg)) {
        a.conn = App::Conn::Unconfigured;
        a.want_tab = 5;
        return;
    }
    a.conn = App::Conn::Connecting;
    auto s = std::make_shared<Session>();
    s->cfg = a.cfg;  // the session works on its own copy; Settings edits never race with a running sync
    s->vault = std::make_unique<Vault>(s->cfg, a.db);
    s->engine = std::make_unique<Engine>(s->cfg, a.db, *s->vault);
    s->edits = std::make_unique<EditManager>(s->cfg, *s->vault);
    a.sess = s;
    a.vault = std::shared_ptr<Vault>(s, s->vault.get());
    a.engine = std::shared_ptr<Engine>(s, s->engine.get());
    a.edits = std::shared_ptr<EditManager>(s, s->edits.get());
    a.engine->on_synced = [&a] { a.post([&a] { a.tree_dirty = true; }); };
    a.run_job([&a, s] {
        Vault* v = s->vault.get();
        std::string err;
        auto still_current = [&a, s] { return a.sess == s; };
        if (!v->connect(err)) {
            a.post([&a, err, still_current] { if (!still_current()) return; a.conn = App::Conn::Error; a.conn_error = err; a.want_tab = 5; });
            return;
        }
        bool exists = false;
        OpResult r = v->load_info(exists);
        if (!r.ok) {
            a.post([&a, e = r.error, still_current] { if (!still_current()) return; a.conn = App::Conn::Error; a.conn_error = e; });
            return;
        }
        if (!exists) {
            a.post([&a, still_current] { if (!still_current()) return; a.conn = App::Conn::NoVault; a.modal = "create-vault"; });
            return;
        }
        bool key = v->has_key();
        if (key) v->try_unlock_from_keychain();
        v->refresh();
        a.post([&a, key, still_current] {
            if (!still_current()) return;
            a.vault_has_key = key;
            a.conn = App::Conn::Ready;
            a.tree_dirty = true;
            a.upload_encrypt = key;
            if (key && !a.vault->unlocked()) a.modal = "unlock";
            a.vault->keep_key_for_session();  // locking hides the window but keeps sync running
            a.engine->start();  // returns immediately; watches and syncs run on the engine's threads
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

// Locks the window only: content can't be viewed until the password is entered again, but the vault
// key stays loaded so sync (including encrypted files) keeps running. Editor buffers are kept in memory.
void lock_ui(App& a, const char* why) {
    if (a.ui_locked) return;
    preview_free(a);
    a.ui_locked = true;
    a.modal.clear();
    a.multi.clear();
    a.lock_error.clear();
    if (GImGui->OpenPopupStack.Size > 0) ImGui::ClosePopupToLevel(0, true);  // file browser, dialogs
    if (why) a.notify(why);
}

// Drops the vault key: encrypted files stop syncing until the password is entered again.
void forget_key(App& a) {
    if (a.vault) a.vault->lock();
    a.ui_locked = false;
    preview_free(a);
    a.notify("Vault key forgotten: encrypted files will not sync until you unlock");
}

void app_shutdown(App& a) {
    if (a.engine) a.engine->stop();  // aborts transfers in flight, so quitting is quick
    if (a.vault && a.vault->connected()) a.vault->s3().cancel = true;
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

struct TreeParams {
    std::string filter;  // lower-case
    int type_filter = 0;
    int sort_col = 0;
    bool sort_desc = false;
};

static bool passes_filter(const TreeParams& p, const RemoteEntry& e) {
    if (!p.filter.empty() && to_lower(e.logical).find(p.filter) == std::string::npos) return false;
    switch (p.type_filter) {
        case 1: return preview_kind(e.logical) == PreviewKind::Text;
        case 2: return preview_kind(e.logical) == PreviewKind::Image;
        case 3: return preview_kind(e.logical) == PreviewKind::Pdf;
        case 4: return e.encrypted;
    }
    return true;
}

const char* status_help(const std::string& st) {
    if (st == "Synced") return "The local copy in the tracked folder matches the server.";
    if (st == "Pending") return "Changed on one side; the next sync pass will upload or download it.";
    if (st == "Server only") return "Upload-only (backup) folder: files that exist only on the server are not downloaded.";
    if (st == "Not updated") return "Upload-only (backup) folder: the server has a newer version that is not downloaded.";
    if (st == "Local only") return "Download-only (mirror) folder: local changes are not uploaded.";
    if (st == "Locked") return "Encrypted file waiting for sync: unlock the vault (the key is needed to encrypt/decrypt).";
    if (st == "Conflict") return "Changed on two sides: see the Conflicts tab.";
    if (st == "Paused") return "The tracked folder is paused (Tracked folders tab).";
    if (st == "Cloud only") return "Not inside any tracked folder: stored in the vault only.";
    return "";
}

// Sync status per logical path from the tracked roots' base rows and open conflicts.
static std::map<std::string, std::string> compute_status(Db& db, const std::vector<RemoteEntry>& entries, bool unlocked) {
    std::map<std::string, std::string> out;
    auto roots = db.roots();
    std::map<int, std::map<std::string, FileRow>> files;
    for (auto& r : roots) files[r.id] = db.files(r.id);
    std::set<std::string> conflicted;
    for (auto& c : db.conflicts())
        for (auto& r : roots)
            if (r.id == c.root_id) conflicted.insert(r.remote_prefix.empty() ? c.rel : r.remote_prefix + "/" + c.rel);
    for (auto& e : entries) {
        if (e.dir_marker) continue;
        std::string st = "Cloud only";
        for (auto& r : roots) {
            std::string pfx = r.remote_prefix.empty() ? "" : r.remote_prefix + "/";
            if (!starts_with(e.logical, pfx)) continue;
            auto& fm = files[r.id];
            auto it = fm.find(e.logical.substr(pfx.size()));
            bool have_base = it != fm.end() && !it->second.base_etag.empty();
            bool remote_same = have_base && it->second.base_etag == e.etag;
            bool local_same = have_base && it->second.l_hash == it->second.base_hash;
            if (r.paused) st = "Paused";
            else if (remote_same && local_same) st = "Synced";
            else if (r.direction == "upload-only" && !have_base) st = "Server only";
            else if (r.direction == "upload-only" && !remote_same && local_same) st = "Not updated";
            else if (r.direction == "download-only" && remote_same && !local_same) st = "Local only";
            else if (e.encrypted && !unlocked) st = "Locked";
            else st = "Pending";
            break;
        }
        if (conflicted.count(e.logical)) st = "Conflict";
        out[e.logical] = st;
    }
    return out;
}

static void mark_tracked(Node* n, const std::vector<RootRow>& roots) {
    for (auto& r : roots) {
        std::string p = r.remote_prefix;
        std::string info = display_path(r.local_path) + " · " + r.direction + (r.paused ? " · paused" : "");
        if (!n->logical.empty() && n->logical == p) { n->tracked_root = n->tracked = true; n->tracked_info = info; }
        else if (p.empty() ? !n->logical.empty() : starts_with(n->logical, p + "/")) { n->tracked = true; n->tracked_info = info; }
    }
    for (auto& k : n->kids) mark_tracked(k.get(), roots);
}

static std::unique_ptr<Node> build_tree(Db& db, Vault* v, const TreeParams& p, std::map<std::string, std::string>& status) {
    auto root = std::make_unique<Node>();
    root->dir = true;
    if (!v) return root;
    auto entries = v->cached_entries();
    status = compute_status(db, entries, v->unlocked());
    bool filtering = !p.filter.empty() || p.type_filter;
    for (auto& e : entries) {
        if (!e.dir_marker && !passes_filter(p, e)) continue;
        auto parts = split(e.logical, '/');
        Node* cur = root.get();
        std::string path;
        size_t ndirs = e.dir_marker ? parts.size() : parts.size() - 1;
        for (size_t i = 0; i < ndirs; i++) {
            path = path.empty() ? parts[i] : path + "/" + parts[i];
            cur = child_dir(cur, parts[i], path);
        }
        if (e.dir_marker) {
            cur->mtime = std::max(cur->mtime, e.mtime);
            continue;
        }
        auto n = std::make_unique<Node>();
        n->name = parts.back();
        n->logical = e.logical;
        n->entry = e;
        n->size = e.size;
        n->mtime = e.mtime;
        n->status = status[e.logical];
        cur->kids.push_back(std::move(n));
    }
    if (filtering) {  // drop folders left empty by the filter
        std::function<bool(Node*)> prune = [&](Node* n) {
            n->kids.erase(std::remove_if(n->kids.begin(), n->kids.end(),
                                         [&](std::unique_ptr<Node>& k) { return k->dir && !prune(k.get()); }),
                          n->kids.end());
            return !n->kids.empty();
        };
        prune(root.get());
    }
    finish(root.get(), p.sort_col, p.sort_desc);
    mark_tracked(root.get(), db.roots());
    return root;
}

// Builds the tree on a worker thread (the listing can be large) and swaps it in when done.
void rebuild_tree(App& a) {
    a.tree_dirty = false;
    uint64_t gen = ++a.tree_gen;
    TreeParams p{to_lower(a.filter), a.type_filter, a.sort_col, a.sort_desc};
    auto v = a.vault;
    a.tree_building = true;
    a.run_job([&a, v, p, gen] {
        std::map<std::string, std::string> status;
        auto holder = std::make_shared<std::unique_ptr<Node>>(build_tree(a.db, v.get(), p, status));
        auto st = std::make_shared<std::map<std::string, std::string>>(std::move(status));
        a.post([&a, gen, holder, st] {
            if (gen != a.tree_gen) return;  // a newer rebuild was requested meanwhile
            a.tree = std::move(*holder);
            a.status_by_logical = std::move(*st);
            a.tree_building = false;
        });
    });
}

const Node* find_node(const Node* n, const std::string& logical) {
    if (!n) return nullptr;
    if (n->logical == logical) return n;
    for (auto& k : n->kids)
        if (k->dir ? starts_with(logical, k->logical + "/") || k->logical == logical : k->logical == logical)
            if (const Node* f = find_node(k.get(), logical)) return f;
    return nullptr;
}

// ---------------------------------------------------------------------------
// lock screen

void draw_lock_screen(App& a) {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##locked", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);
    float w = 420;
    ImGui::SetCursorPos(ImVec2((vp->WorkSize.x - w) * 0.5f, vp->WorkSize.y * 0.28f));
    ImGui::BeginGroup();
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + w);
    ImGui::Text(ICON_FA_LOCK "  s3vault is locked");
    ImGui::Spacing();
    ImGui::TextDisabled("%s/%s", a.cfg.storage.bucket.c_str(), a.vault ? a.vault->prefix().c_str() : "");
    // Sync status stays visible: it shows no file content.
    size_t nx = a.engine ? a.engine->transfers().size() : 0;
    if (a.engine && a.engine->syncing()) ImGui::TextColored(ImVec4(0.45f, 0.85f, 0.5f, 1), ICON_FA_ROTATE "  Syncing in the background%s",
                                                             nx ? (" · " + std::to_string(nx) + " transfer(s)").c_str() : "");
    else if (a.engine && a.engine->last_sync())
        ImGui::TextDisabled(ICON_FA_CIRCLE_CHECK "  Sync keeps running · last %s", format_local_time(a.engine->last_sync()).c_str());
    if (a.edits && a.edits->any_dirty()) ImGui::TextColored(ImVec4(1, 0.75f, 0.3f, 1), ICON_FA_PEN "  Unsaved editor changes are kept");
    ImGui::Spacing();
    ImGui::SetNextItemWidth(w);
    if (!a.lock_busy && !ImGui::IsAnyItemActive()) ImGui::SetKeyboardFocusHere();
    bool enter = ImGui::InputTextWithHint("##pw", "Vault password", a.lock_pw, sizeof a.lock_pw,
                                          ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::BeginDisabled(a.lock_busy || !a.lock_pw[0]);
    if ((ImGui::Button(ICON_FA_UNLOCK " Unlock", ImVec2(w, 0)) || enter) && a.lock_pw[0] && !a.lock_busy) {
        std::string pw = a.lock_pw;
        explicit_bzero(a.lock_pw, sizeof a.lock_pw);
        a.lock_busy = true;
        auto v = a.vault;
        a.run_job([&a, v, pw]() mutable {
            OpResult r = v ? v->verify_password(pw) : OpResult::fail("not connected");
            wipe(pw);
            a.post([&a, r] {
                a.lock_busy = false;
                if (r.ok) {
                    a.ui_locked = false;
                    a.tree_dirty = true;
                    a.last_input = glfwGetTime();
                } else {
                    a.lock_error = r.error;
                }
            });
        });
    }
    ImGui::EndDisabled();
    if (a.lock_busy) ImGui::TextDisabled("Checking…");
    if (!a.lock_error.empty()) ImGui::TextColored(ImVec4(1, 0.45f, 0.4f, 1), "%s", a.lock_error.c_str());
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextDisabled("Sync keeps running while locked. To also stop syncing encrypted files:");
    if (ImGui::SmallButton("Forget the vault key")) {
        forget_key(a);
        a.modal = "unlock";
    }
    ImGui::PopTextWrapPos();
    ImGui::EndGroup();
    ImGui::End();
    draw_modals(a);  // only the unlock dialog can be open here
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
            if (a.vault->unlocked()) {
                if (ImGui::Button(ICON_FA_LOCK " Lock")) lock_ui(a, nullptr);
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("Hide the vault until the password is entered again.\nSync keeps running in the background.");
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
    if (a.tree_dirty && a.conn == App::Conn::Ready) rebuild_tree(a);

    // Idle → lock the window (not the key: sync continues). Only in "idle" mode.
    if (a.vault && a.vault->unlocked() && !a.ui_locked && a.cfg.security.remember == "idle" &&
        a.cfg.security.idle_minutes > 0 && glfwGetTime() - a.last_input > a.cfg.security.idle_minutes * 60.0)
        lock_ui(a, "Locked after inactivity; sync continues");
    preview_tick(a);

    if (a.ui_locked) {
        draw_lock_screen(a);
        return;
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
    size_t nedit = a.edits ? a.edits->ids().size() : 0;
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
        std::string el = std::string(ICON_FA_PEN_TO_SQUARE " Editor") + (nedit ? " (" + std::to_string(nedit) + ")" : "") + "###edits";
        if (tab(4, el)) { draw_edits_tab(a); ImGui::EndTabItem(); }
        if (tab(5, ICON_FA_GEAR " Settings###settings")) { draw_settings_tab(a); ImGui::EndTabItem(); }
        ImGui::EndTabBar();
    }
    a.want_tab = -1;
    ImGui::End();

    draw_modals(a);
    draw_file_browser(a);

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
