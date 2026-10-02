// s3vault desktop UI (Dear ImGui). Shared state for the panels.
#pragma once
#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "config/config.h"
#include "edit/edit.h"
#include "index/db.h"
#include "preview/preview.h"
#include "sync/engine.h"
#include "theme.h"
#include "vault/vault.h"

struct GLFWwindow;

namespace s3v::ui {

// A node of the vault tree (built from the remote listing; folders implied by keys or markers).
struct Node {
    std::string name;
    std::string logical;  // full path; "" for the root
    bool dir = false;
    RemoteEntry entry;  // files only
    uint64_t size = 0;  // files: object size; folders: sum
    int64_t mtime = 0;  // files: LastModified; folders: newest child
    std::vector<std::unique_ptr<Node>> kids;
    std::string status;  // see status_help()
    bool tracked = false;       // inside a tracked (auto-synced) folder
    bool tracked_root = false;  // is the vault side of a tracked folder
    std::string tracked_info;   // "~/Pictures · upload-only"
};

enum class PreviewState { Empty, Loading, Ready, Error };

struct Preview {
    PreviewState state = PreviewState::Empty;
    PreviewKind kind = PreviewKind::None;
    std::string logical;
    std::string key;
    std::string error;
    bool too_large = false;
    // Text
    std::string text;
    std::vector<uint32_t> line_starts;
    bool binary = false;
    // Image (texture owned by the UI thread)
    unsigned tex = 0;
    int w = 0, h = 0;
    float zoom = 0;  // 0 = fit
    // PDF
    std::shared_ptr<PdfDoc> pdf;
    int page = 1;
    bool page_loading = false;
    double last_used = 0;
    uint64_t generation = 0;  // bumps on every load/free to drop stale background results
};

struct Toast {
    std::string text;
    bool error = false;
    double until = 0;
};

// One connection: its own Config snapshot + vault + engine + edit sessions. Background jobs hold a
// shared_ptr to it, so reconnecting never has to wait for them (the old session dies with its last job).
struct Session {
    Config cfg;
    std::unique_ptr<Vault> vault;
    std::unique_ptr<Engine> engine;
    std::unique_ptr<EditManager> edits;
    ~Session() {
        if (engine) engine->stop();
        engine.reset();
        edits.reset();
        vault.reset();
    }
};

enum class View { Files, Trash, Transfers, Conflicts, Editor, Settings };

struct App {
    GLFWwindow* win = nullptr;
    Config cfg;
    Db db;
    std::shared_ptr<Session> sess;
    // Aliases into `sess` (keep the session alive while held).
    std::shared_ptr<Vault> vault;
    std::shared_ptr<Engine> engine;
    std::shared_ptr<EditManager> edits;

    // Connection / vault state (set by background jobs)
    enum class Conn { Unconfigured, Connecting, Error, NoVault, Ready };
    std::atomic<Conn> conn{Conn::Unconfigured};
    std::string conn_error;
    bool vault_has_key = false;
    bool browse_locked = false;  // user chose to look around without unlocking (names only)

    // Navigation (Finder model: you are always "in" a folder; new items go there)
    View view = View::Files;
    std::string cwd;                       // current vault folder ("" = root)
    std::vector<std::string> back, fwd;    // history
    float sidebar_w = 232, inspector_w = 330;
    bool focus_search = false;

    // Tree (whole vault; the list shows the subtree of cwd)
    std::unique_ptr<Node> tree;
    std::string selected;          // logical path of the selected node
    std::set<std::string> multi;   // multi-selection (files and folders)
    std::string current_dir;       // = cwd (kept for code that predates navigation)
    int sort_col = 0;
    bool sort_desc = false;
    char filter[128] = "";
    int type_filter = 0;  // 0 all, 1 text, 2 images, 3 pdf, 4 encrypted
    bool tree_dirty = true;
    int64_t listed_at = 0;
    uint64_t tree_gen = 0;      // bumps per rebuild request; stale background builds are dropped
    bool tree_building = false;
    std::map<std::string, std::string> status_by_logical;
    std::set<std::string> force_open;  // folders opened programmatically (--script expand:)

    Preview preview;

    // Conflicts selection
    std::set<int64_t> conflict_sel;

    // Vault trash
    std::vector<TrashEntry> trash;
    std::set<std::string> trash_sel;  // trash object keys
    bool trash_dirty = true, trash_loading = false;

    // Sheets (modal dialogs)
    std::string modal;  // current sheet id; "" none
    std::string modal_arg;
    char pw1[256] = "", pw2[256] = "", pw_old[256] = "";
    char text_buf[1024] = "";
    char dir_buf[1024] = "";
    std::string modal_error;
    bool modal_busy = false;
    std::vector<std::string> pending_uploads;  // local paths waiting for the upload sheet
    bool upload_encrypt = true;
    int upload_on_exists = 0;  // 0 replace, 1 keep both, 2 skip
    int edit_focus = 0;        // editor document to bring to front
    int edit_close_id = 0;     // document waiting for the "unsaved changes" answer
    // Window lock (the key stays loaded; sync continues)
    bool ui_locked = false;
    char lock_pw[256] = "";
    std::string lock_error;
    bool lock_busy = false;
    bool quit_requested = false, quit_confirmed = false;

    // Setup assistant
    int setup_step = 0;          // 0 storage, 1 vault password, 2 first folder
    bool offer_first_folder = false;

    // Settings
    Config form;                 // storage fields being edited (applied with "Connect")
    char secret_buf[256] = "";
    std::string probe_report;
    bool probing = false;

    Toast toast;
    double last_input = 0;
    bool had_input = false;

    // ---- background jobs ----
    std::mutex ui_mu;
    std::deque<std::function<void()>> ui_queue;  // run on the UI thread
    std::vector<std::thread> jobs;
    std::atomic<int> busy{0};
    void run_job(std::function<void()> fn);
    void post(std::function<void()> fn);
    void drain_ui_queue();
    void join_jobs();

    void notify(const std::string& t, bool error = false);
};

// app.cpp — lifecycle, layout, sidebar, navigation
void app_init(App& a);
void app_frame(App& a);
void app_shutdown(App& a);
void connect_async(App& a);
void rebuild_tree(App& a);
void lock_ui(App& a, const char* why);
void forget_key(App& a);
void navigate(App& a, const std::string& dir, bool record = true);
void set_view(App& a, View v);
bool key_needed(App& a);       // vault has a password but its key is not loaded
void save_settings(App& a);    // persist a.cfg (and push live values into the running session)

// screens.cpp — full-window states
void draw_setup(App& a);
void draw_lock_screen(App& a);

// files_view.cpp
void draw_files_view(App& a);
// views.cpp
void draw_conflicts_view(App& a);
void draw_transfers_view(App& a);
void draw_trash_view(App& a);
// settings_view.cpp
void draw_settings_view(App& a);
void settings_connect(App& a);  // apply the storage form and reconnect
void storage_fields(App& a);
// editor_view.cpp
void draw_edits_tab(App& a);
void save_all_docs(App& a);
// dialogs.cpp
void draw_modals(App& a);
bool strength_meter(const char* pw, int min_len);
void password_pair(App& a, bool& acceptable);
// ops.cpp — vault operations started from the UI
void start_uploads(App& a, const std::vector<std::string>& files);
void choose_and_upload(App& a);
void download_all(App& a, const std::string& dest_parent, bool decrypt);
void start_download_all(App& a, bool decrypt);
// on_exists: 0 replace, 1 keep both, 2 skip
void upload_files(App& a, std::vector<std::string> files, std::string dest_dir, bool encrypt, int on_exists);
void open_in_editor(App& a, const RemoteEntry& e);
void download_to_dialog(App& a, const RemoteEntry& e);
void add_tracked_folder(App& a);
void refresh_listing(App& a);
void test_storage(App& a);

const Node* find_node(const Node* n, const std::string& logical);
const char* status_help(const std::string& status);

// file_browser.cpp — built-in picker (external dialogs open behind the window on GNOME)
enum class BrowseMode { OpenMany, Folder, Save };
void browse(App& a, BrowseMode mode, const std::string& title, std::function<void(std::vector<std::string>)> on_ok,
            const std::string& suggested_name = "");
void draw_file_browser(App& a);

// preview_view.cpp
void preview_load(App& a, const RemoteEntry& e);
void preview_free(App& a);
void draw_preview(App& a, const Node* sel, float height);
void preview_tick(App& a);

}  // namespace s3v::ui
