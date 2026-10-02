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
            a.post([&a, err, still_current] { if (!still_current()) return; a.conn = App::Conn::Error; a.conn_error = err; });
            return;
        }
        bool exists = false;
        OpResult r = v->load_info(exists);
        if (!r.ok) {
            a.post([&a, e = r.error, still_current] { if (!still_current()) return; a.conn = App::Conn::Error; a.conn_error = e; });
            return;
        }
        if (!exists) {
            a.post([&a, still_current] { if (!still_current()) return; a.conn = App::Conn::NoVault; });
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
            a.browse_locked = false;  // the lock screen asks for the password when the key isn't loaded
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
    a.browse_locked = true;  // stay in the window, with the "locked" banner
    preview_free(a);
    a.tree_dirty = true;
    a.notify("Key forgotten — encrypted files won't sync until you unlock");
}

bool key_needed(App& a) { return a.conn == App::Conn::Ready && a.vault_has_key && a.vault && !a.vault->unlocked(); }

void navigate(App& a, const std::string& dir, bool record) {
    if (record && dir != a.cwd) {
        a.back.push_back(a.cwd);
        a.fwd.clear();
    }
    if (a.preview.state != PreviewState::Empty) preview_free(a);
    a.cwd = dir;
    a.current_dir = dir;
    a.selected.clear();
    a.multi.clear();
    if (a.filter[0]) {
        a.filter[0] = 0;
        a.tree_dirty = true;
    }
    a.view = View::Files;
}

void set_view(App& a, View v) {
    if (v != View::Files && a.preview.state != PreviewState::Empty) preview_free(a);
    if (v == View::Trash) a.trash_dirty = true;
    if (v == View::Settings) {
        a.form.storage = a.cfg.storage;  // start from what is in use
        a.probe_report.clear();
    }
    a.view = v;
}

void save_settings(App& a) {
    a.cfg.save(config_path());
    // Values the running engine reads on every pass apply at once.
    if (a.sess) {
        Config& c = a.sess->cfg;
        c.sync.poll_seconds = a.cfg.sync.poll_seconds;
        c.sync.concurrency = a.cfg.sync.concurrency;
        c.sync.trash_days = a.cfg.sync.trash_days;
        c.sync.bandwidth_kbps = a.cfg.sync.bandwidth_kbps;
        c.preview = a.cfg.preview;
        c.security.idle_minutes = a.cfg.security.idle_minutes;
        if (a.vault && a.vault->connected())
            a.vault->s3().max_bytes_per_sec = a.cfg.sync.bandwidth_kbps > 0 ? int64_t(a.cfg.sync.bandwidth_kbps) * 1024 : 0;
    }
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
// sidebar

static bool side_item(const char* icon, const ImVec4& icon_col, const char* label, bool selected, const std::string& badge_text = "",
                      const ImVec4* badge_col = nullptr, const ImVec4* dot = nullptr) {
    float w = ImGui::GetContentRegionAvail().x, h = ImGui::GetFrameHeight() + 4;
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::PushID(label);
    ImGui::PushID(icon);
    bool click = ImGui::InvisibleButton("##si", ImVec2(w, h));
    ImGui::PopID();
    ImGui::PopID();
    bool hov = ImGui::IsItemHovered();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (selected) dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), col(P.dark ? ImVec4(1, 1, 1, 0.09f) : ImVec4(0, 0, 0, 0.07f)), 7);
    else if (hov) dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), col(P.hover), 7);
    float ty = p.y + (h - ImGui::GetTextLineHeight()) / 2;
    ImVec2 is = ImGui::CalcTextSize(icon);
    dl->AddText(ImVec2(p.x + 10 + (18 - is.x) / 2, ty), col(icon_col), icon);
    float right = p.x + w - 8;
    if (!badge_text.empty()) {
        ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 0.8f);
        ImVec2 bs = ImGui::CalcTextSize(badge_text.c_str());
        float bh = bs.y + 4, bw = std::max(bh, bs.x + 12);
        ImVec2 b0(right - bw, p.y + (h - bh) / 2);
        if (badge_col) dl->AddRectFilled(b0, ImVec2(b0.x + bw, b0.y + bh), col(*badge_col), bh / 2);
        dl->AddText(ImVec2(b0.x + (bw - bs.x) / 2, b0.y + 2), col(badge_col ? P.on_accent : P.dim), badge_text.c_str());
        ImGui::PopFont();
        right -= bw + 6;
    }
    if (dot) {
        dl->AddCircleFilled(ImVec2(right - 4, p.y + h / 2), 4, col(*dot), 12);
        right -= 14;
    }
    // Label, cut with an ellipsis if needed.
    std::string l = label;
    float maxw = right - (p.x + 36);
    if (ImGui::CalcTextSize(l.c_str()).x > maxw) {
        while (l.size() > 1 && ImGui::CalcTextSize((l + "…").c_str()).x > maxw) {
            size_t k = l.size() - 1;
            while (k > 0 && (static_cast<unsigned char>(l[k]) & 0xC0) == 0x80) k--;
            l.resize(k);
        }
        l += "…";
        tip(label);
    }
    dl->AddText(ImVec2(p.x + 36, ty), col(P.text), l.c_str());
    return click;
}

static void side_section(const char* title) {
    ImGui::Dummy(ImVec2(0, 8));
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 10);
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 0.78f);
    ImGui::TextColored(P.dim, "%s", title);
    ImGui::PopFont();
    ImGui::Dummy(ImVec2(0, 1));
}

static void sidebar(App& a, float w, float h) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, P.sidebar);
    ImGui::BeginChild("##sidebar", ImVec2(w, h), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar);
    ImGui::PopStyleColor();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 wp = ImGui::GetWindowPos();
    dl->AddLine(ImVec2(wp.x + w - 1, wp.y), ImVec2(wp.x + w - 1, wp.y + h), col(P.border));
    float footer_h = 92;

    ImGui::SetCursorPos(ImVec2(16, 16));
    ImGui::TextColored(P.accent, ICON_FA_VAULT);
    ImGui::SameLine(0, 8);
    title_text("s3vault", 1.12f);
    ImGui::SetCursorPosX(16);
    small_dim("%s", a.cfg.storage.bucket.empty() ? "not connected" : a.cfg.storage.bucket.c_str());
    ImGui::Dummy(ImVec2(0, 4));

    ImGui::SetCursorPosX(8);
    ImGui::BeginChild("##sidelist", ImVec2(w - 16, h - ImGui::GetCursorPosY() - footer_h), ImGuiChildFlags_None, ImGuiWindowFlags_None);
    bool files = a.view == View::Files;
    side_section("VAULT");
    if (side_item(ICON_FA_HARD_DRIVE, P.accent, "All Files", files && a.cwd.empty())) navigate(a, "");
    if (side_item(ICON_FA_TRASH, P.dim, "Trash", a.view == View::Trash)) set_view(a, View::Trash);

    auto roots = a.db.roots();
    side_section("SYNCED FOLDERS");
    auto conflicts = a.db.conflicts();
    for (auto& r : roots) {
        size_t nconf = 0;
        for (auto& c : conflicts) nconf += c.root_id == r.id;
        bool missing = !stat_path(r.local_path, true).is_dir;
        ImVec4 dotc = r.paused ? P.grey : missing ? P.red : nconf ? P.orange : (a.engine && a.engine->syncing()) ? P.blue : P.green;
        std::string label = path_basename(r.local_path);
        bool sel = files && !a.cwd.empty() && (a.cwd == r.remote_prefix || starts_with(a.cwd, r.remote_prefix + "/"));
        ImGui::PushID(r.id);
        if (side_item(ICON_FA_FOLDER, P.folder, label.c_str(), sel, "", nullptr, &dotc)) navigate(a, r.remote_prefix);
        std::string t = display_path(r.local_path) + "  ↔  /" + r.remote_prefix + "\n" +
                        (r.paused ? "Paused" : missing ? "Folder missing on this computer" : nconf ? std::to_string(nconf) + " conflict(s)" : "In sync");
        tip(t);
        if (ImGui::BeginPopupContextItem("##rootmenu")) {
            if (ImGui::MenuItem(ICON_FA_FOLDER_OPEN "   Show in Vault")) navigate(a, r.remote_prefix);
            RootRow rr = r;
            if (ImGui::MenuItem(r.paused ? ICON_FA_PLAY "   Resume Syncing" : ICON_FA_PAUSE "   Pause Syncing")) {
                rr.paused = !rr.paused;
                a.db.update_root(rr);
                if (a.engine) a.engine->request_sync();
            }
            if (ImGui::MenuItem(ICON_FA_GEAR "   Sync Settings…")) set_view(a, View::Settings);
            ImGui::Separator();
            if (ImGui::MenuItem(ICON_FA_LINK_SLASH "   Stop Syncing…")) {
                a.modal_arg = std::to_string(r.id);
                a.modal = "remove-root";
            }
            ImGui::EndPopup();
        }
        ImGui::PopID();
    }
    if (side_item(ICON_FA_PLUS, P.dim, "Add Folder…", false)) add_tracked_folder(a);

    side_section("ACTIVITY");
    auto ts = a.engine ? a.engine->transfers() : std::vector<Transfer>{};
    if (side_item(ICON_FA_ARROW_RIGHT_ARROW_LEFT, P.dim, "Transfers", a.view == View::Transfers, ts.empty() ? "" : std::to_string(ts.size()), &P.accent))
        set_view(a, View::Transfers);
    if (side_item(ICON_FA_CODE_MERGE, conflicts.empty() ? P.dim : P.orange, "Conflicts", a.view == View::Conflicts,
                  conflicts.empty() ? "" : std::to_string(conflicts.size()), &P.orange))
        set_view(a, View::Conflicts);
    size_t ndocs = a.edits ? a.edits->ids().size() : 0;
    bool dirty = a.edits && a.edits->any_dirty();
    if (ndocs && side_item(ICON_FA_PEN_TO_SQUARE, P.dim, "Editor", a.view == View::Editor, std::to_string(ndocs), dirty ? &P.orange : &P.grey))
        set_view(a, View::Editor);
    ImGui::EndChild();

    // Footer: sync status, lock, settings
    ImGui::SetCursorPos(ImVec2(0, h - footer_h));
    ImVec2 fp = ImGui::GetCursorScreenPos();
    dl->AddLine(fp, ImVec2(fp.x + w - 1, fp.y), col(P.border));
    ImGui::SetCursorPos(ImVec2(16, h - footer_h + 12));
    {
        using C = App::Conn;
        std::string line1, line2;
        ImVec4 c = P.dim;
        const char* icon = ICON_FA_CIRCLE_CHECK;
        size_t nx = ts.size();
        if (a.conn == C::Connecting) { line1 = "Connecting…"; icon = ICON_FA_CLOUD; }
        else if (a.conn == C::Error) { line1 = "Can't reach storage"; line2 = "Open Settings for details"; c = P.red; icon = ICON_FA_CIRCLE_EXCLAMATION; }
        else if (a.conn != C::Ready) { line1 = "Not connected"; icon = ICON_FA_CLOUD; }
        else if (key_needed(a)) { line1 = "Locked"; line2 = "Encrypted files are paused"; c = P.orange; icon = ICON_FA_LOCK; }
        else if (nx || (a.engine && a.engine->syncing())) { line1 = nx ? "Syncing " + std::to_string(nx) + " files" : "Checking for changes"; c = P.accent; icon = ICON_FA_ROTATE; }
        else if (!conflicts.empty()) { line1 = "Needs your attention"; line2 = std::to_string(conflicts.size()) + " conflict(s)"; c = P.orange; icon = ICON_FA_TRIANGLE_EXCLAMATION; }
        else { line1 = "Up to date"; c = P.green; }
        if (line2.empty() && a.engine && a.engine->last_sync()) line2 = "Checked " + format_local_time(a.engine->last_sync()).substr(11);
        ImGui::TextColored(c, "%s", icon);
        ImGui::SameLine(0, 8);
        ImGui::BeginGroup();
        ImGui::TextUnformatted(line1.c_str());
        if (!line2.empty()) small_dim("%s", line2.c_str());
        ImGui::EndGroup();
    }
    ImGui::SetCursorPos(ImVec2(10, h - 40));
    bool can_lock = a.vault && a.vault_has_key && a.vault->unlocked();
    if (icon_button(ICON_FA_LOCK, can_lock ? "Lock the window — sync keeps running" : "Nothing to lock", false, can_lock)) lock_ui(a, nullptr);
    ImGui::SameLine(0, 2);
    if (icon_button(ICON_FA_ARROWS_ROTATE, "Sync now", a.engine && a.engine->syncing(), a.conn == App::Conn::Ready)) {
        if (a.engine) a.engine->request_sync();
        refresh_listing(a);
    }
    ImGui::SameLine(0, 2);
    if (icon_button(ICON_FA_GEAR, "Settings", a.view == View::Settings)) set_view(a, View::Settings);
    ImGui::EndChild();
}

// ---------------------------------------------------------------------------
// frame

static void toast(App& a) {
    if (a.toast.text.empty() || glfwGetTime() > a.toast.until) return;
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    float alpha = std::min(1.0f, float(a.toast.until - glfwGetTime()) * 3.0f);
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + vp->WorkSize.x / 2 + a.sidebar_w / 2, vp->WorkPos.y + vp->WorkSize.y - 24), 0, ImVec2(0.5f, 1));
    ImGui::SetNextWindowBgAlpha(0.96f * alpha);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16, 10));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 20);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1);
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, alpha);
    ImGui::PushStyleColor(ImGuiCol_WindowBg, P.dark ? ImVec4(0.2f, 0.2f, 0.22f, 1) : ImVec4(1, 1, 1, 1));
    ImGui::Begin("##toast", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoFocusOnAppearing |
                     ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoSavedSettings);
    if (a.toast.error) ImGui::TextColored(P.red, ICON_FA_CIRCLE_EXCLAMATION);
    else ImGui::TextColored(P.green, ICON_FA_CIRCLE_CHECK);
    ImGui::SameLine(0, 8);
    ImGui::PushTextWrapPos(560);
    ImGui::TextUnformatted(a.toast.text.c_str());
    ImGui::PopTextWrapPos();
    ImGui::End();
    ImGui::PopStyleColor();
    ImGui::PopStyleVar(4);
}

static bool setup_needed(App& a) {
    using C = App::Conn;
    if (a.conn == C::Unconfigured || a.conn == C::NoVault) return true;
    if (a.offer_first_folder && a.conn == C::Ready) return true;
    // A connection error before anything was ever set up keeps the assistant on screen.
    if ((a.conn == C::Error || a.conn == C::Connecting) && a.listed_at == 0 && a.db.roots().empty() && a.view != View::Settings) return true;
    return false;
}

void app_frame(App& a) {
    a.drain_ui_queue();
    if (a.tree_dirty && a.conn == App::Conn::Ready) rebuild_tree(a);

    // Theme: follow the setting (system = the desktop's light/dark preference, read at start).
    static int applied = -1;
    static bool sys_dark = system_prefers_dark();
    int want = a.cfg.ui.theme == "dark" ? 1 : a.cfg.ui.theme == "light" ? 0 : (sys_dark ? 1 : 0);
    if (want != applied) {
        apply_theme(want == 1);
        applied = want;
    }

    // Lock the window after inactivity (the key stays loaded; sync continues).
    if (a.vault && a.vault->unlocked() && !a.ui_locked && a.cfg.security.idle_minutes > 0 && a.cfg.security.remember != "ask" &&
        glfwGetTime() - a.last_input > a.cfg.security.idle_minutes * 60.0)
        lock_ui(a, nullptr);
    preview_tick(a);

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##main", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                     ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    float W = vp->WorkSize.x, H = vp->WorkSize.y;

    bool locked_screen = a.ui_locked || (key_needed(a) && !a.browse_locked);
    if (locked_screen) {
        draw_lock_screen(a);
    } else if (setup_needed(a)) {
        draw_setup(a);
    } else {
        float sw = W < 760 ? 0 : a.sidebar_w;
        if (sw > 0) {
            ImGui::SetCursorPos(ImVec2(0, 0));
            sidebar(a, sw, H);
        }
        ImGui::SetCursorPos(ImVec2(sw, 0));
        ImGui::BeginChild("##content", ImVec2(W - sw, H), ImGuiChildFlags_None, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        switch (a.view) {
            case View::Files: draw_files_view(a); break;
            case View::Trash: draw_trash_view(a); break;
            case View::Transfers: draw_transfers_view(a); break;
            case View::Conflicts: draw_conflicts_view(a); break;
            case View::Editor: draw_edits_tab(a); break;
            case View::Settings: draw_settings_view(a); break;
        }
        ImGui::EndChild();
    }
    ImGui::End();

    draw_modals(a);
    draw_file_browser(a);
    toast(a);
}

}  // namespace s3v::ui
