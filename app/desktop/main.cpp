// s3vault desktop (Linux, Windows): GLFW + OpenGL 3.3 + Dear ImGui, same stack as gpu-hud.
#include "backends/imgui_impl_opengl3_loader.h"
#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <strings.h>
#include <sys/wait.h>
#endif

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <vector>
#include <cstdlib>
#include <string>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include "imgui.h"
#include "platform.h"
#include "store/curl_dl.h"
#include "util/compat.h"
#include "util/fs.h"
#include "util/strings.h"
#include "util/subprocess.h"
#ifdef _WIN32
#include "util/win_text.h"
#endif

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

using namespace s3v;

static ui::App* g_app = nullptr;

// --script "step;step;…" drives the UI for screenshots and smoke tests without synthetic input:
//   lang:<en|zh|ja|ko>  palette:<query>  locate:<setting>  tab:<vault|folders|conflicts|transfers|edits|settings>  expand:<dir>  select:<path>  preview
//   conflicts:all  compare  edit:<path>  type:<text>  save  lock  form:<key>=<value>  upload:<local file>  browse:<files|folder|save>  unlock  reconnect  modal:<id>  sleep:<seconds>  idle  shot:<file.png>  quit
struct Script {
    std::vector<std::string> steps;
    size_t i = 0;
    double wait_until = 0;
    double idle_since = -1;
};

static bool save_png(GLFWwindow* w, const std::string& path) {
    int fw, fh;
    glfwGetFramebufferSize(w, &fw, &fh);
    std::vector<unsigned char> px(size_t(fw) * size_t(fh) * 4);
    glPixelStorei(GL_PACK_ALIGNMENT, 1);
    glReadPixels(0, 0, fw, fh, GL_RGBA, GL_UNSIGNED_BYTE, px.data());
    stbi_flip_vertically_on_write(1);
    return stbi_write_png(path.c_str(), fw, fh, 4, px.data(), fw * 4) != 0;
}

// Runs script steps; returns a screenshot path when this frame should be captured.
static std::string script_step(Script& s, ui::App& a) {
    double now = glfwGetTime();
    while (s.i < s.steps.size()) {
        if (now < s.wait_until) return "";
        std::string st = s.steps[s.i];
        size_t c = st.find(':');
        std::string cmd = st.substr(0, c), arg = c == std::string::npos ? "" : st.substr(c + 1);
        if (cmd == "idle") {
            bool idle = a.busy == 0 && a.conn != ui::App::Conn::Connecting && a.preview.state != ui::PreviewState::Loading &&
                        !a.preview.page_loading && !(a.engine && a.engine->syncing());
            if (!idle) { s.idle_since = -1; return ""; }
            if (s.idle_since < 0) s.idle_since = now;
            if (now - s.idle_since < 0.5) return "";
            s.idle_since = -1;
        } else if (cmd == "sleep") {
            s.wait_until = now + atof(arg.c_str());
            s.i++;
            return "";
        } else if (cmd == "tab") {
            if (arg == "vault" || arg == "files") ui::set_view(a, ui::View::Files);
            else if (arg == "trash") ui::set_view(a, ui::View::Trash);
            else if (arg == "conflicts") ui::set_view(a, ui::View::Conflicts);
            else if (arg == "transfers") ui::set_view(a, ui::View::Transfers);
            else if (arg == "edits" || arg == "editor") ui::set_view(a, ui::View::Editor);
            else if (arg == "settings" || arg == "folders") ui::set_view(a, ui::View::Settings);
        } else if (cmd == "theme") {
            a.cfg.ui.theme = arg;
        } else if (cmd == "lang") {
            a.cfg.ui.language = arg;
        } else if (cmd == "help") {  // help:<0 concepts|1 glossary|2 shortcuts>
            ui::open_help(a, atoi(arg.c_str()));
        } else if (cmd == "status") {  // status:<0 tasks|1 logs>
            ui::open_status(a, atoi(arg.c_str()));
        } else if (cmd == "palette") {  // palette:<query>
            ui::open_palette(a, arg.c_str());
        } else if (cmd == "locate") {  // locate:<English setting title>
            ui::set_view(a, ui::View::Settings);
            ui::prefs::locate(arg.c_str());
        } else if (cmd == "cd") {
            ui::navigate(a, arg);
        } else if (cmd == "expand") {
            std::string p;
            for (auto& part : split(arg, '/')) { p = p.empty() ? part : p + "/" + part; a.force_open.insert(p); }
        } else if (cmd == "select") {
            a.selected = arg;
            a.current_dir = path_dirname(arg);
        } else if (cmd == "preview") {
            for (auto& e : a.vault->cached_entries())
                if (e.logical == a.selected && !e.dir_marker) ui::preview_load(a, e);
        } else if (cmd == "conflicts") {
            for (auto& k : a.db.conflicts()) a.conflict_sel.insert(k.id);
        } else if (cmd == "edit") {
            for (auto& e : a.vault->cached_entries())
                if (e.logical == arg && !e.dir_marker) ui::open_in_editor(a, e);
        } else if (cmd == "type") {  // append text to the focused editor document (smoke tests)
            if (a.edits)
                for (int id : a.edits->ids())
                    if (EditDoc* d = a.edits->doc(id)) d->text += arg;
        } else if (cmd == "download-all") {  // download-all:<dir>|<decrypted|encrypted>
            size_t bar = arg.find('|');
            ui::download_all(a, arg.substr(0, bar), bar == std::string::npos || arg.substr(bar + 1) != "encrypted");
        } else if (cmd == "form") {  // form:<key>=<value>: fill the Settings form only (e.g. placeholders for screenshots)
            size_t eq = arg.find('=');
            if (eq != std::string::npos) a.form.set(arg.substr(0, eq), arg.substr(eq + 1));
        } else if (cmd == "save") {
            ui::save_all_docs(a);
        } else if (cmd == "lock") {
            ui::lock_ui(a, nullptr);
        } else if (cmd == "upload") {
            ui::upload_files(a, {arg}, a.current_dir, a.vault_has_key, 1);
        } else if (cmd == "browse") {
            ui::BrowseMode m = arg == "folder" ? ui::BrowseMode::Folder : arg == "save" ? ui::BrowseMode::Save : ui::BrowseMode::OpenMany;
            ui::browse(a, m, m == ui::BrowseMode::Folder ? "Choose a folder to sync" : "Upload to /", [](std::vector<std::string>) {}, "example.txt");
        } else if (cmd == "unlock") {
            // Test-only: password from $S3VAULT_PASSWORD, never from the script text.
            if (const char* pw = getenv("S3VAULT_PASSWORD"); pw && a.vault) {
                OpResult r = a.vault->unlocked() ? a.vault->verify_password(pw) : a.vault->unlock(pw);
                if (r.ok) {
                    a.modal.clear();
                    a.ui_locked = false;
                    a.tree_dirty = true;
                    if (a.engine) a.engine->request_sync();
                }
                else fprintf(stderr, "script unlock: %s\n", r.error.c_str());
            }
        } else if (cmd == "reconnect") {
            ui::connect_async(a);
        } else if (cmd == "compare") {
            auto list = a.db.conflicts();
            if (!list.empty()) { a.modal_arg = std::to_string(list[0].id); a.modal = "compare"; }
        } else if (cmd == "modal") {
            a.modal = arg;
        } else if (cmd == "shot") {
            s.i++;
            s.wait_until = now + 0.3;  // let the next frames settle before the following step
            return arg;
        } else if (cmd == "quit") {
            a.quit_confirmed = true;
        }
        s.i++;
    }
    return "";
}

#ifdef _WIN32
// Windows: the fonts every Windows 10/11 install has (Segoe UI, Microsoft YaHei for CJK, Consolas).
static std::string fc_match(const char* pattern) {
    const wchar_t* w = _wgetenv(L"WINDIR");
    std::string dir = (w && *w ? slashes(from_wide(w)) : std::string("C:/Windows")) + "/Fonts/";
    std::string pat = pattern;
    std::vector<const char*> files;
    if (pat.find("lang=ja") != std::string::npos) files = {"YuGothR.ttc", "meiryo.ttc", "msgothic.ttc"};
    else if (pat.find("lang=ko") != std::string::npos) files = {"malgun.ttf", "gulim.ttc"};
    else if (pat.find("lang=zh") != std::string::npos) files = {"msyh.ttc", "simsun.ttc"};
    else if (pat == "monospace") files = {"consola.ttf", "cour.ttf"};
    else files = {"segoeui.ttf", "arial.ttf"};
    for (const char* f : files)
        if (stat_path(dir + f, true).is_file) return dir + f;
    return "";
}
#else
static std::string fc_match(const char* pattern) {
    std::string out;
    if (run_capture({"fc-match", "-f", "%{file}", pattern}, "", &out, nullptr, 4096, 3000) != 0) return "";
    out = trim(out);
    std::string e = path_ext_lower(out);
    if (!stat_path(out, true).is_file || (e != "ttf" && e != "otf" && e != "ttc")) return "";
    return out;
}
#endif

static std::string icon_font_path() {
#ifdef _WIN32
    wchar_t exe[32768] = {};
    DWORD n = GetModuleFileNameW(nullptr, exe, 32768);
    std::string dir = n > 0 ? path_dirname(slashes(from_wide(exe, int(n)))) : ".";
#else
    char exe[4096] = {};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    std::string dir = n > 0 ? path_dirname(std::string(exe, size_t(n))) : ".";
#endif
    for (std::string p : {dir + "/fonts/fa-solid-900.ttf", dir + "/../share/s3vault/fonts/fa-solid-900.ttf", std::string(S3V_FONT_DIR) + "/fa-solid-900.ttf",
                          std::string(S3V_FONT_DIR_BUILD) + "/fa-solid-900.ttf", dir + "/fa-solid-900.ttf"})
        if (stat_path(p, true).is_file) return p;
    return "";
}

// CJK text (file names, and the UI in 中文 / 日本語 / 한국어): the font for the UI language first, so its glyph
// shapes are used, then the other two for anything it lacks (e.g. Hangul in a Chinese font on Windows).
struct FontFace {
    std::string file;
    int index = 0;  // face inside a .ttc collection
};

#ifndef _WIN32
static FontFace fc_face(const char* pattern) {
    std::string out;
    if (run_capture({"fc-match", "-f", "%{file}\n%{index}", pattern}, "", &out, nullptr, 4096, 3000) != 0) return {};
    auto l = split(out, '\n');
    if (l.empty() || !stat_path(trim(l[0]), true).is_file) return {};
    return {trim(l[0]), l.size() > 1 ? atoi(l[1].c_str()) : 0};
}
#else
static FontFace fc_face(const char* pattern) { return {fc_match(pattern), 0}; }
#endif

static std::vector<FontFace> cjk_fonts() {
    std::vector<std::string> order;
    switch (ui::language()) {
        case ui::Lang::Ja: order = {"ja", "zh-cn", "ko"}; break;
        case ui::Lang::Ko: order = {"ko", "zh-cn", "ja"}; break;
        default: order = {"zh-cn", "ja", "ko"}; break;
    }
    std::vector<FontFace> out;
    for (auto& l : order) {
        FontFace f = fc_face(("sans-serif:lang=" + l).c_str());
        bool dup = false;
        for (auto& o : out) dup |= o.file == f.file && o.index == f.index;
        if (!f.file.empty() && !dup) out.push_back(f);
    }
    return out;
}

static void build_fonts() {
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();
    // Text fonts must not answer for the icon range (DejaVu maps legacy fi/fl ligatures at U+F001/F002).
    static const ImWchar no_pua[] = {0xE000, 0xF8FF, 0};
    auto first = [](std::initializer_list<const char*> paths, const char* pattern) {
        for (const char* p : paths)
            if (stat_path(p, true).is_file) return std::string(p);
        return fc_match(pattern);
    };
    std::string base = first({"/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf", "/usr/share/fonts/noto/NotoSans-Regular.ttf",
                              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/TTF/DejaVuSans.ttf"},
                             "sans-serif:lang=en");
    ImFontConfig cfg;
    cfg.OversampleH = 2;
    cfg.GlyphExcludeRanges = no_pua;
    if (base.empty() || !io.Fonts->AddFontFromFileTTF(base.c_str(), 0.0f, &cfg)) io.Fonts->AddFontDefault();
    // CJK (merged; glyphs are loaded on demand by the dynamic font atlas).
    std::vector<FontFace> cjk = cjk_fonts();
    for (auto& f : cjk) {
        if (f.file == base) continue;
        ImFontConfig m;
        m.MergeMode = true;
        m.FontNo = f.index;
        m.GlyphExcludeRanges = no_pua;
        io.Fonts->AddFontFromFileTTF(f.file.c_str(), 0.0f, &m);
    }
    std::string icons = icon_font_path();
    if (!icons.empty()) {
        ImFontConfig m;
        m.MergeMode = true;
        io.Fonts->AddFontFromFileTTF(icons.c_str(), 0.0f, &m);
    }
    // Monospaced font for code, text previews and the editor (with the same CJK + icon fallbacks).
    std::string mono = first({"/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"},
                             "monospace");
    if (!mono.empty()) {
        ImFontConfig mc;
        mc.GlyphExcludeRanges = no_pua;
        ui::g_mono = io.Fonts->AddFontFromFileTTF(mono.c_str(), 0.0f, &mc);
        for (auto& f : cjk) {
            if (!ui::g_mono) break;
            ImFontConfig m;
            m.MergeMode = true;
            m.FontNo = f.index;
            m.GlyphExcludeRanges = no_pua;
            io.Fonts->AddFontFromFileTTF(f.file.c_str(), 0.0f, &m);
        }
        if (ui::g_mono && !icons.empty()) {
            ImFontConfig m;
            m.MergeMode = true;
            io.Fonts->AddFontFromFileTTF(icons.c_str(), 0.0f, &m);
        }
    }
}

#ifndef _WIN32
// The NVIDIA GL driver segfaults on the first draw when it cannot allocate a graphics context (e.g. a
// local LLM holds most of the GB10's unified memory). The GUI therefore runs in a child process; if that
// child dies from a signal before its first frame reached the screen, we start again with Mesa's
// software renderer, which needs no GPU memory.
static int g_ready_fd = -1;
static pid_t g_child = -1;

static void use_software_gl() {
    setenv("__GLX_VENDOR_LIBRARY_NAME", "mesa", 1);
    setenv("LIBGL_ALWAYS_SOFTWARE", "1", 1);
}

// Returns in the child (normal startup); the parent never returns.
static void guard_gpu_start(int argc, char** argv) {
    int fds[2];
    if (pipe(fds) != 0) return;
    pid_t pid = fork();
    if (pid < 0) return;
    if (pid == 0) {
        close(fds[0]);
        g_ready_fd = fds[1];
        return;
    }
    close(fds[1]);
    g_child = pid;
    for (int sig : {SIGINT, SIGTERM, SIGHUP})
        signal(sig, [](int s) { if (g_child > 0) kill(g_child, s); });
    char c = 0;
    bool ready = read(fds[0], &c, 1) == 1;  // the child writes one byte after its first frame is shown
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    if (!ready && WIFSIGNALED(st) && (WTERMSIG(st) == SIGSEGV || WTERMSIG(st) == SIGBUS || WTERMSIG(st) == SIGABRT)) {
        fprintf(stderr, "s3vault: the GPU driver crashed while opening the window (GPU memory full?); "
                        "retrying with software rendering\n");
        use_software_gl();
        std::vector<char*> args(argv, argv + argc);
        args.push_back(const_cast<char*>("--software"));
        args.push_back(nullptr);
        execv("/proc/self/exe", args.data());
        _exit(1);
    }
    _exit(WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st));
}
#else
static int g_ready_fd = -1;
static void use_software_gl() {}
static void guard_gpu_start(int, char**) {}
#endif

int main(int argc, char** argv) {
    bool software = getenv("S3VAULT_SOFTWARE_GL") != nullptr;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--software")) software = true;
    if (software) use_software_gl();
    else guard_gpu_start(argc, argv);  // before any thread exists (fork)

    Script script;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--home" && i + 1 < argc) set_env("S3VAULT_HOME", argv[++i]);
        else if (a == "--script" && i + 1 < argc) script.steps = split(argv[++i], ';');
        else if (a == "--software") {}
        else if (a == "-h" || a == "--help") {
            printf("s3vault — sync files with S3-compatible storage\n  --home DIR   use DIR for config and data\n"
                   "  --software   render on the CPU (automatic if the GPU driver cannot open a window)\n"
                   "See also: s3vault-cli --help\n");
            return 0;
        }
    }
    platform::install_exit_cleanup();
    // One-time library initialisation must happen here, before GL and before any worker thread:
    // curl_global_init (OpenSSL) is not thread-safe, and loading these libraries while the NVIDIA GL
    // driver renders on another thread crashed the app.
    curl_api();
    platform::keychain_preload();

    glfwSetErrorCallback([](int, const char* d) { fprintf(stderr, "glfw: %s\n", d); });
    if (!glfwInit()) return 1;
    ui::App app;
    g_app = &app;
    app.cfg.load(config_path());
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    // Script runs (tests, screenshots) use an invisible window so they never appear on — or take clicks from —
    // the user's desktop.
    if (!script.steps.empty()) glfwWindowHint(GLFW_VISIBLE, GLFW_FALSE);
    glfwWindowHint(GLFW_DECORATED, GLFW_FALSE);  // no system title bar: s3vault draws its own (window_chrome.cpp)
    glfwWindowHint(GLFW_MAXIMIZED, app.cfg.ui.maximized ? GLFW_TRUE : GLFW_FALSE);
    glfwWindowHintString(GLFW_X11_CLASS_NAME, "s3vault");
    glfwWindowHintString(GLFW_X11_INSTANCE_NAME, "s3vault");
    app.win = glfwCreateWindow(std::max(720, app.cfg.ui.width), std::max(480, app.cfg.ui.height), "s3vault", nullptr, nullptr);
    if (!app.win) return 1;
    glfwSetWindowSizeLimits(app.win, 720, 480, GLFW_DONT_CARE, GLFW_DONT_CARE);
    glfwMakeContextCurrent(app.win);
    glfwSwapInterval(1);

    glfwSetDropCallback(app.win, [](GLFWwindow*, int n, const char** paths) {
        std::vector<std::string> f(paths, paths + n);
        g_app->post([f] { ui::start_uploads(*g_app, f); });
    });
    glfwSetWindowCloseCallback(app.win, [](GLFWwindow* w) {
        if (g_app->quit_confirmed) return;
        if (g_app->edits && g_app->edits->any_dirty()) {
            glfwSetWindowShouldClose(w, GLFW_FALSE);
            g_app->quit_requested = true;
            g_app->modal = "quit-unsaved";
        }
    });

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;  // layout is fixed; nothing about files is persisted by ImGui
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ui::set_language(app.cfg.ui.language);
    build_fonts();  // colours and metrics: ui::apply_theme(), applied by the first frame
    ui::Lang font_lang = ui::language();
    ImGui_ImplGlfw_InitForOpenGL(app.win, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    ui::app_init(app);

    // Script mode reports the slowest frame (UI-thread stalls) on exit.
    double worst_frame = 0, prev_frame = -1;
    int slow_frames = 0;
    while (!glfwWindowShouldClose(app.win) && !app.quit_confirmed) {
        bool active = !script.steps.empty() || app.busy > 0 || (app.engine && (app.engine->syncing() || !app.engine->transfers().empty())) ||
                      app.preview.state == ui::PreviewState::Loading;
        if (ui::motion::animating()) glfwPollEvents();  // mid-animation: every frame (vsync paces it)
        else glfwWaitEventsTimeout(active ? 0.05 : 0.5);
        ImGui::GetStyle().FontSizeBase = app.cfg.ui.font_size;
        if (ui::language() != font_lang) {  // language switched in Settings: CJK glyph shapes follow it
            font_lang = ui::language();
            build_fonts();
        }
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        if (io.MouseDelta.x != 0 || io.MouseDelta.y != 0 || io.MouseWheel != 0 || io.InputQueueCharacters.Size ||
            ImGui::IsAnyMouseDown()) {
            app.last_input = glfwGetTime();
            app.had_input = true;
        }
        std::string shot = script.steps.empty() ? "" : script_step(script, app);
        double t_frame = glfwGetTime();
        ui::app_frame(app);
        ImGui::Render();
        int w, h;
        glfwGetFramebufferSize(app.win, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(ui::P.bg.x, ui::P.bg.y, ui::P.bg.z, 1);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        if (!shot.empty()) {
            // Render one more frame first so freshly opened popups/trees have their final layout.
            static int settle = 0;
            if (settle++ < 3) { script.i--; script.wait_until = 0; }
            else { settle = 0; if (!save_png(app.win, shot)) fprintf(stderr, "cannot write %s\n", shot.c_str()); }
        }
        glfwSwapBuffers(app.win);
        if (g_ready_fd >= 0) {  // first frame is on screen: tell the guard process the GPU path works
            (void)!write(g_ready_fd, "1", 1);
            close(g_ready_fd);
            g_ready_fd = -1;
        }
        double took = glfwGetTime() - t_frame;  // work done on the UI thread this frame (excludes waiting for events)
        if (prev_frame >= 0) {
            worst_frame = std::max(worst_frame, took);
            if (took > 0.1) slow_frames++;
        }
        prev_frame = t_frame;
        if (app.quit_requested && app.quit_confirmed) break;
    }
    if (!script.steps.empty())
        fprintf(stderr, "ui-thread: slowest frame %.1f ms, frames over 100 ms: %d\n", worst_frame * 1000, slow_frames);
    app.cfg.ui.maximized = glfwGetWindowAttrib(app.win, GLFW_MAXIMIZED) == GLFW_TRUE;
    if (!app.cfg.ui.maximized) glfwGetWindowSize(app.win, &app.cfg.ui.width, &app.cfg.ui.height);
    ui::app_shutdown(app);
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(app.win);
    glfwTerminate();
    return 0;
}
