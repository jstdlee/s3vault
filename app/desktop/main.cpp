// s3vault desktop (Linux): GLFW + OpenGL 3.3 + Dear ImGui, same stack as gpu-hud.
#include "backends/imgui_impl_opengl3_loader.h"
#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "backends/imgui_impl_glfw.h"
#include "backends/imgui_impl_opengl3.h"
#include "imgui.h"
#include "platform.h"
#include "util/fs.h"
#include "util/strings.h"
#include "util/subprocess.h"

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

using namespace s3v;

static ui::App* g_app = nullptr;

// --script "step;step;…" drives the UI for screenshots and smoke tests without synthetic input:
//   tab:<vault|folders|conflicts|transfers|edits|settings>  expand:<dir>  select:<path>  preview
//   conflicts:all  compare  edit:<path>  upload:<local file>  browse:<files|folder|save>  reconnect  modal:<id>  sleep:<seconds>  idle  shot:<file.png>  quit
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
            const char* names[] = {"vault", "folders", "conflicts", "transfers", "edits", "settings"};
            for (int t = 0; t < 6; t++) if (arg == names[t]) a.want_tab = t;
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
                if (e.logical == arg && !e.dir_marker) ui::open_in_editor(a, e, true);
        } else if (cmd == "upload") {
            ui::upload_files(a, {arg}, a.current_dir, a.vault_has_key, 1);
        } else if (cmd == "browse") {
            ui::BrowseMode m = arg == "folder" ? ui::BrowseMode::Folder : arg == "save" ? ui::BrowseMode::Save : ui::BrowseMode::OpenMany;
            ui::browse(a, m, "Script", [](std::vector<std::string>) {}, "example.txt");
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

static std::string fc_match(const char* pattern) {
    std::string out;
    if (run_capture({"fc-match", "-f", "%{file}", pattern}, "", &out, nullptr, 4096, 3000) != 0) return "";
    out = trim(out);
    std::string e = path_ext_lower(out);
    if (!stat_path(out, true).is_file || (e != "ttf" && e != "otf" && e != "ttc")) return "";
    return out;
}

static std::string icon_font_path() {
    char exe[4096] = {};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    std::string dir = n > 0 ? path_dirname(std::string(exe, size_t(n))) : ".";
    for (std::string p : {dir + "/../share/s3vault/fonts/fa-solid-900.ttf", std::string(S3V_FONT_DIR) + "/fa-solid-900.ttf",
                          std::string(S3V_FONT_DIR_BUILD) + "/fa-solid-900.ttf", dir + "/fa-solid-900.ttf"})
        if (stat_path(p, true).is_file) return p;
    return "";
}

static void build_fonts() {
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();
    std::string base;
    for (const char* p : {"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/TTF/DejaVuSans.ttf",
                          "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf"})
        if (stat_path(p, true).is_file) { base = p; break; }
    if (base.empty()) base = fc_match("sans-serif:lang=en");
    // Text fonts must not answer for the icon range (DejaVu maps legacy fi/fl ligatures at U+F001/F002).
    static const ImWchar no_pua[] = {0xE000, 0xF8FF, 0};
    ImFontConfig cfg;
    cfg.OversampleH = 2;
    cfg.GlyphExcludeRanges = no_pua;
    if (base.empty() || !io.Fonts->AddFontFromFileTTF(base.c_str(), 0.0f, &cfg)) io.Fonts->AddFontDefault();
    // CJK file names (merged; glyphs are loaded on demand by the dynamic font atlas).
    std::string cjk = fc_match("sans-serif:lang=zh-cn");
    if (!cjk.empty() && cjk != base) {
        ImFontConfig m;
        m.MergeMode = true;
        m.GlyphExcludeRanges = no_pua;
        io.Fonts->AddFontFromFileTTF(cjk.c_str(), 0.0f, &m);
    }
    std::string icons = icon_font_path();
    if (!icons.empty()) {
        ImFontConfig m;
        m.MergeMode = true;
        m.GlyphMinAdvanceX = 16.0f;
        io.Fonts->AddFontFromFileTTF(icons.c_str(), 0.0f, &m);
    }
}

static void apply_style() {
    ImGui::StyleColorsDark();
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding = 0;
    s.FrameRounding = 4;
    s.PopupRounding = 6;
    s.TabRounding = 4;
    s.GrabRounding = 4;
    s.FramePadding = ImVec2(8, 5);
    s.ItemSpacing = ImVec2(8, 6);
    s.TreeLinesFlags = ImGuiTreeNodeFlags_DrawLinesToNodes;
    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg] = ImVec4(0.10f, 0.11f, 0.13f, 1);
    c[ImGuiCol_ChildBg] = ImVec4(0.10f, 0.11f, 0.13f, 1);
    c[ImGuiCol_PopupBg] = ImVec4(0.13f, 0.14f, 0.17f, 1);
    c[ImGuiCol_Header] = ImVec4(0.20f, 0.36f, 0.58f, 0.55f);
    c[ImGuiCol_HeaderHovered] = ImVec4(0.24f, 0.42f, 0.66f, 0.70f);
    c[ImGuiCol_HeaderActive] = ImVec4(0.26f, 0.46f, 0.72f, 0.85f);
    c[ImGuiCol_Button] = ImVec4(0.20f, 0.30f, 0.45f, 0.75f);
    c[ImGuiCol_ButtonHovered] = ImVec4(0.26f, 0.40f, 0.60f, 1);
    c[ImGuiCol_Tab] = ImVec4(0.14f, 0.16f, 0.20f, 1);
    c[ImGuiCol_TabSelected] = ImVec4(0.22f, 0.34f, 0.52f, 1);
    c[ImGuiCol_TabHovered] = ImVec4(0.26f, 0.40f, 0.60f, 1);
    c[ImGuiCol_TableRowBgAlt] = ImVec4(1, 1, 1, 0.025f);
}

int main(int argc, char** argv) {
    Script script;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--home" && i + 1 < argc) setenv("S3VAULT_HOME", argv[++i], 1);
        else if (a == "--script" && i + 1 < argc) script.steps = split(argv[++i], ';');
        else if (a == "-h" || a == "--help") {
            printf("s3vault — sync files with S3-compatible storage\n  --home DIR   use DIR for config and data\n"
                   "See also: s3vault-cli --help\n");
            return 0;
        }
    }
    platform::install_exit_cleanup();

    glfwSetErrorCallback([](int, const char* d) { fprintf(stderr, "glfw: %s\n", d); });
    if (!glfwInit()) return 1;
    ui::App app;
    g_app = &app;
    app.cfg.load(config_path());
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHintString(GLFW_X11_CLASS_NAME, "s3vault");
    glfwWindowHintString(GLFW_X11_INSTANCE_NAME, "s3vault");
    app.win = glfwCreateWindow(std::max(640, app.cfg.ui.width), std::max(420, app.cfg.ui.height), "s3vault", nullptr, nullptr);
    if (!app.win) return 1;
    glfwMakeContextCurrent(app.win);
    glfwSwapInterval(1);

    glfwSetDropCallback(app.win, [](GLFWwindow*, int n, const char** paths) {
        std::vector<std::string> f(paths, paths + n);
        g_app->post([f] { ui::start_uploads(*g_app, f); });
    });
    glfwSetWindowCloseCallback(app.win, [](GLFWwindow* w) {
        if (g_app->quit_confirmed) return;
        if (g_app->edits && g_app->edits->any_unsaved()) {
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
    apply_style();
    build_fonts();
    ImGui_ImplGlfw_InitForOpenGL(app.win, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    ui::app_init(app);

    // Script mode reports the slowest frame (UI-thread stalls) on exit.
    double worst_frame = 0, prev_frame = -1;
    int slow_frames = 0;
    while (!glfwWindowShouldClose(app.win) && !app.quit_confirmed) {
        bool active = !script.steps.empty() || app.busy > 0 || (app.engine && (app.engine->syncing() || !app.engine->transfers().empty())) ||
                      app.preview.state == ui::PreviewState::Loading;
        glfwWaitEventsTimeout(active ? 0.05 : 0.5);
        ImGui::GetStyle().FontSizeBase = app.cfg.ui.font_size;
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
        glClearColor(0.10f, 0.11f, 0.13f, 1);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        if (!shot.empty()) {
            // Render one more frame first so freshly opened popups/trees have their final layout.
            static int settle = 0;
            if (settle++ < 3) { script.i--; script.wait_until = 0; }
            else { settle = 0; if (!save_png(app.win, shot)) fprintf(stderr, "cannot write %s\n", shot.c_str()); }
        }
        glfwSwapBuffers(app.win);
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
    glfwGetWindowSize(app.win, &app.cfg.ui.width, &app.cfg.ui.height);
    ui::app_shutdown(app);
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(app.win);
    glfwTerminate();
    return 0;
}
