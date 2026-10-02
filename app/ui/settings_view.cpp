// Settings: one page of cards in the "Magpie" preferences style. Everything except the storage account is
// saved the moment it changes; the storage card applies with "Connect" (it reconnects).
#include <GLFW/glfw3.h>

#include <algorithm>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "crypto/gpg.h"
#include "imgui.h"
#include "platform.h"
#include "util/fs.h"
#include "util/secure.h"
#include "util/strings.h"
#include "util/subprocess.h"

namespace s3v::ui {

template <typename T>
static int index_of(const std::vector<T>& v, const T& x, int def = 0) {
    for (size_t i = 0; i < v.size(); i++)
        if (v[i] == x) return int(i);
    return def;
}

static bool storage_changed(App& a) {
    const StorageConfig &f = a.form.storage, &c = a.cfg.storage;
    return f.provider != c.provider || f.account_id != c.account_id || f.endpoint != c.endpoint || f.region != c.region ||
           f.addressing != c.addressing || f.bucket != c.bucket || f.prefix != c.prefix || f.access_key_id != c.access_key_id ||
           a.secret_buf[0];
}

void settings_connect(App& a) {
    if (a.secret_buf[0]) {
        bool ok = platform::keychain_store(Vault::secret_account(a.form.storage), trim(a.secret_buf));
        explicit_bzero(a.secret_buf, sizeof a.secret_buf);
        if (!ok) a.notify("The keychain is not available; set S3VAULT_SECRET_KEY in the environment instead", true);
    }
    a.cfg.storage = a.form.storage;
    save_settings(a);
    connect_async(a);
}

// Storage fields shared with the setup assistant.
void storage_fields(App& a) {
    StorageConfig& s = a.form.storage;
    std::vector<std::string> ids = {"r2", "aws", "minio", "b2", "wasabi", "custom"};
    int pi = index_of(ids, s.provider);
    if (prefs::choice("Provider", "Where your files are stored", &pi, {"Cloudflare R2", "AWS S3", "MinIO", "B2", "Wasabi", "Other"}))
        s.provider = ids[size_t(pi)];
    if (s.provider == "r2") prefs::text("Account ID", "Shown in the Cloudflare dashboard under R2", s.account_id, 300, "32 hex characters");
    if (s.provider != "r2") prefs::text("Region", "e.g. us-east-1, eu-central-1", s.region, 300, "auto");
    if (s.provider == "minio" || s.provider == "custom")
        prefs::text("Endpoint", "The S3 address of your server", s.endpoint, 300, "https://s3.example.com");
    prefs::text("Bucket", "The bucket that holds the vault", s.bucket, 300, "my-bucket");
    prefs::text("Vault folder", "A folder inside the bucket; several vaults can share one bucket", s.prefix, 300, "s3vault/main");
    prefs::text("Access key ID", "From an API token with read & write access to the bucket", s.access_key_id, 300);
    prefs::row("Secret access key", "Kept in your keychain, never in a file", 300, [&] {
        ImGui::SetNextItemWidth(300);
        bool env = getenv("S3VAULT_SECRET_KEY") != nullptr;
        ImGui::InputTextWithHint("##secret", env ? "using $S3VAULT_SECRET_KEY" : a.conn == App::Conn::Unconfigured ? "paste the secret key" : "saved — paste to replace", a.secret_buf, sizeof a.secret_buf,
                                 ImGuiInputTextFlags_Password);
    });
}

void draw_settings_view(App& a) {
    float top = page_header("Settings");
    ImGui::SetCursorPos(ImVec2(0, top));
    ImGui::BeginChild("##settings");
    prefs::page_begin(760);
    bool ready = a.conn == App::Conn::Ready;
    bool dirty = false;

    // ---- Storage ----
    prefs::section("Storage");
    prefs::card_begin();
    {
        using C = App::Conn;
        std::string st;
        ImVec4 sc = P.dim;
        switch (a.conn.load()) {
            case C::Ready: st = "Connected"; sc = P.green; break;
            case C::Connecting: st = "Connecting…"; break;
            case C::NoVault: st = "No vault here yet"; sc = P.orange; break;
            case C::Error: st = "Can't connect"; sc = P.red; break;
            default: st = "Not set up"; sc = P.orange; break;
        }
        std::string where = a.cfg.storage.bucket.empty() ? "Fill in the fields below" : a.cfg.storage.bucket + " / " + a.cfg.storage.prefix;
        if (a.conn == C::Error) where = a.conn_error;
        prefs::info("Status", where.c_str(), st.c_str(), &sc);
    }
    storage_fields(a);
    {
        bool changed = storage_changed(a);
        float w = 230;
        prefs::row("Apply", changed ? "Connect again to use the new details" : "Check that the bucket allows safe writes", w, [&] {
            if (button("Test", Btn::Secondary, ImVec2(80, 0), ready && !a.probing)) test_storage(a);
            ImGui::SameLine(0, 8);
            if (button(changed ? "Connect" : "Reconnect", changed ? Btn::Primary : Btn::Secondary, ImVec2(142, 0))) settings_connect(a);
        });
    }
    prefs::card_end();
    if (a.probing || !a.probe_report.empty()) {
        ImGui::Dummy(ImVec2(0, 4));
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 30);
        if (a.probing) { spinner(7, P.dim); ImGui::SameLine(); ImGui::TextDisabled("Testing the bucket…"); }
        else {
            ImGui::BeginGroup();
            for (auto& l : split(a.probe_report, '\n'))
                if (!l.empty()) ImGui::TextColored(starts_with(l, "✗") ? P.red : starts_with(l, "✓") ? P.green : P.dim, "%s", l.c_str());
            ImGui::EndGroup();
        }
    }

    // ---- Security ----
    prefs::section("Security");
    prefs::card_begin();
    if (prefs::action("Vault password", "Protects the key that encrypts your files",
                      a.vault_has_key ? "Change…" : "Set…", Btn::Secondary, ready))
        a.modal = a.vault_has_key ? "change-password" : "set-password";
    {
        std::vector<int> mins = {0, 5, 15, 30, 60};
        int i = index_of(mins, a.cfg.security.idle_minutes, 2);
        if (prefs::choice("Lock after", "Hides the window when you're away; sync keeps running", &i, {"Never", "5 min", "15 min", "30 min", "1 hour"})) {
            a.cfg.security.idle_minutes = mins[size_t(i)];
            dirty = true;
        }
    }
    {
        std::vector<std::string> modes = {"idle", "keychain", "ask"};
        std::string cur = a.cfg.security.remember == "session" ? "idle" : a.cfg.security.remember;
        int i = index_of(modes, cur);
        if (prefs::choice("Remember the key", "Keychain unlocks by itself for 7 days; Ask stops background sync of encrypted files",
                          &i, {"Until I quit", "Keychain", "Ask each time"})) {
            a.cfg.security.remember = modes[size_t(i)];
            dirty = true;
        }
    }
    if (prefs::action("Export key", "A backup of the key file, or the recovery key for your password manager", "Export…",
                      Btn::Secondary, ready && a.vault_has_key))
        a.modal = "export-key";
    if (prefs::action("Forget the key now", "Encrypted files stop syncing until you unlock again", "Forget",
                      Btn::Destructive, a.vault && a.vault->unlocked()))
        forget_key(a);
    prefs::card_end();

    // ---- Synced folders ----
    prefs::section("Synced folders");
    auto roots = a.db.roots();
    for (auto r : roots) {
        prefs::card_begin();
        bool exists = stat_path(r.local_path, true).is_dir;
        std::string title = display_path(r.local_path) + "   " + ICON_FA_ARROW_RIGHT_ARROW_LEFT + "   /" + r.remote_prefix;
        ImGui::PushID(r.id);
        prefs::info(title.c_str(), exists ? "Kept in sync automatically" : "This folder is missing on this computer", exists ? "" : "Missing",
                    exists ? nullptr : &P.red);
        bool changed = false;
        std::vector<std::string> dirs = {"two-way", "upload-only", "download-only"};
        int di = index_of(dirs, r.direction);
        if (prefs::choice("Direction", "Back up only never downloads; Mirror only never uploads", &di, {"Both ways", "Back up only", "Mirror only"})) {
            r.direction = dirs[size_t(di)];
            changed = true;
        }
        if (a.vault_has_key && prefs::toggle("Encrypt new files", "Existing files keep their current form", &r.encrypt)) changed = true;
        if (prefs::toggle("Pause", "Stop syncing this folder for now", &r.paused)) changed = true;
        if (prefs::action("Stop syncing", "Nothing is deleted on either side", "Stop Syncing…", Btn::Destructive)) {
            a.modal_arg = std::to_string(r.id);
            a.modal = "remove-root";
        }
        ImGui::PopID();
        if (changed) {
            a.db.update_root(r);
            if (a.engine) a.engine->request_sync();
            a.tree_dirty = true;
        }
        prefs::card_end();
        ImGui::Dummy(ImVec2(0, 6));
    }
    prefs::card_begin();
    if (prefs::action(roots.empty() ? "No folders are synced yet" : "Add another folder", "A folder on this computer stays in sync with one in the vault",
                      "Add Folder…", Btn::Primary, ready))
        add_tracked_folder(a);
    prefs::card_end();

    // ---- Sync ----
    prefs::section("Sync");
    prefs::card_begin();
    {
        std::vector<int> v = {30, 60, 300, 900};
        int i = index_of(v, a.cfg.sync.poll_seconds, 1);
        if (prefs::choice("Check the server", "How often to look for changes made on other devices", &i, {"30 s", "1 min", "5 min", "15 min"})) {
            a.cfg.sync.poll_seconds = v[size_t(i)];
            dirty = true;
        }
    }
    {
        std::vector<int> v = {2, 4, 8, 16};
        int i = index_of(v, a.cfg.sync.concurrency, 2);
        if (prefs::choice("Files at once", "More is faster on a good connection", &i, {"2", "4", "8", "16"})) {
            a.cfg.sync.concurrency = v[size_t(i)];
            dirty = true;
        }
    }
    {
        std::vector<int> v = {0, 1024, 5120, 20480};
        int i = index_of(v, a.cfg.sync.bandwidth_kbps, 0);
        if (prefs::choice("Speed limit", "Per transfer; leaves room for other apps", &i, {"Off", "1 MB/s", "5 MB/s", "20 MB/s"})) {
            a.cfg.sync.bandwidth_kbps = v[size_t(i)];
            dirty = true;
        }
    }
    {
        std::vector<int> v = {7, 30, 90, 365};
        int i = index_of(v, a.cfg.sync.trash_days, 1);
        if (prefs::choice("Keep deleted files", "How long the vault trash keeps things you delete", &i, {"7 days", "30 days", "90 days", "1 year"})) {
            a.cfg.sync.trash_days = v[size_t(i)];
            dirty = true;
        }
    }
    if (prefs::text("This device", "Its name in conflict copies and the activity log", a.cfg.sync.device_name, 240, "computer name")) dirty = true;
    prefs::card_end();

    // ---- Backup ----
    prefs::section("Backup");
    prefs::card_begin();
    if (prefs::action("Download everything", "Plain copies of every file, decrypted", "Download…", Btn::Secondary, ready))
        start_download_all(a, true);
    if (prefs::action("Download everything, as stored", "Encrypted files plus the key file; opens later with your password", "Download…",
                      Btn::Secondary, ready))
        start_download_all(a, false);
    prefs::card_end();

    // ---- Appearance ----
    prefs::section("Appearance");
    prefs::card_begin();
    {
        std::vector<std::string> v = {"system", "light", "dark"};
        int i = index_of(v, a.cfg.ui.theme);
        if (prefs::choice("Appearance", "Follows your desktop's light or dark setting by default", &i, {"System", "Light", "Dark"})) {
            a.cfg.ui.theme = v[size_t(i)];
            dirty = true;
        }
    }
    {
        std::vector<float> v = {13.5f, 15.0f, 17.25f, 19.5f};
        int i = 1;
        for (size_t k = 0; k < v.size(); k++)
            if (std::abs(a.cfg.ui.font_size - v[k]) < 0.3f) i = int(k);
        if (prefs::choice("Text size", "Everything in the window, larger or smaller", &i, {"90%", "100%", "115%", "130%"})) {
            a.cfg.ui.font_size = v[size_t(i)];
            dirty = true;
        }
    }
    {
        bool adv = a.cfg.ui.advanced != 0;
        if (prefs::toggle("Show advanced settings", "Program paths and preview limits", &adv)) {
            a.cfg.ui.advanced = adv;
            dirty = true;
        }
    }
    prefs::card_end();

    if (a.cfg.ui.advanced) {
        prefs::section("Advanced");
        prefs::card_begin();
        struct Deps {
            std::string gpg_cfg, gpg_exe, gpg_ver, pdf;
            bool gpg_ok = false, keychain = false;
            double at = -100;
        };
        static Deps d;
        if (glfwGetTime() - d.at > 3.0 || d.gpg_cfg != a.cfg.deps.gpg) {
            Gpg g(a.cfg.deps.gpg);
            d.gpg_cfg = a.cfg.deps.gpg;
            d.gpg_exe = g.exe();
            d.gpg_ver = g.version();
            d.gpg_ok = g.available();
            d.pdf = find_executable(a.cfg.deps.pdftoppm == "auto" ? "pdftoppm" : a.cfg.deps.pdftoppm);
            d.keychain = platform::keychain_available();
            d.at = glfwGetTime();
        }
        std::string gv = d.gpg_ok ? "GnuPG " + d.gpg_ver : "Not found";
        prefs::info("Encryption program", d.gpg_ok ? display_path(d.gpg_exe).c_str() : "Install gnupg", gv.c_str(), d.gpg_ok ? &P.green : &P.red);
        prefs::info("PDF previews", d.pdf.empty() ? "Install poppler-utils to preview PDFs" : display_path(d.pdf).c_str(),
                    d.pdf.empty() ? "Off" : "On", d.pdf.empty() ? &P.orange : &P.green);
        prefs::info("Keychain", "Stores the storage secret and, if you choose, the vault key", d.keychain ? "Available" : "Not available",
                    d.keychain ? &P.green : &P.orange);
        if (prefs::text("gpg program", "Path, or auto to find it", a.cfg.deps.gpg, 240, "auto")) dirty = true;
        if (prefs::text("pdftoppm program", "Path, or auto to find it", a.cfg.deps.pdftoppm, 240, "auto")) dirty = true;
        if (prefs::number("Text preview limit (MB)", "Larger files are not previewed or edited", &a.cfg.preview.text_max_mb, 1, 64)) dirty = true;
        if (prefs::number("Image preview limit (MB)", "Larger images are not previewed", &a.cfg.preview.image_max_mb, 1, 512)) dirty = true;
        if (prefs::number("Image size limit (megapixels)", "Guards against images that expand enormously", &a.cfg.preview.image_max_mpix, 1, 400)) dirty = true;
        if (prefs::number("PDF preview limit (MB)", "Larger PDFs are not previewed", &a.cfg.preview.pdf_max_mb, 1, 1024)) dirty = true;
        prefs::info("Settings file", "Secrets are never stored in it", display_path(config_path()).c_str());
        prefs::card_end();
    }

    ImGui::Dummy(ImVec2(0, 10));
    ImGui::SetCursorPosX(std::max(16.0f, (ImGui::GetContentRegionAvail().x - 760) / 2) + 4);
    small_dim("Changes are saved as you make them.");
    prefs::page_end();
    if (dirty || prefs::g_dirty) {
        a.form.security = a.cfg.security;
        a.form.sync = a.cfg.sync;
        a.form.ui = a.cfg.ui;
        a.form.deps = a.cfg.deps;
        a.form.preview = a.cfg.preview;
        save_settings(a);
    }
    ImGui::EndChild();
}

}  // namespace s3v::ui
