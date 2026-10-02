// Frameless window (no system title bar): window buttons at the top right, drag the top strip to move,
// double-click it to zoom, drag any edge or corner to resize. Works the same on X11 and Windows.
#include <GLFW/glfw3.h>

#include <algorithm>

#include "app.h"
#include "imgui_internal.h"

namespace s3v::ui {

namespace {

constexpr float kTitleZone = 52;  // height of the draggable top strip (toolbar / page header / sidebar header)
constexpr float kEdge = 5;        // resize grab width

enum Edge { None = 0, L = 1, R = 2, T = 4, B = 8 };

struct Drag {
    bool moving = false;
    int edges = None;
    double sx = 0, sy = 0;  // cursor in screen coordinates at the start
    int wx = 0, wy = 0, ww = 0, wh = 0;
};
Drag g_drag;

void screen_cursor(GLFWwindow* w, double& x, double& y) {
    int wx, wy;
    glfwGetWindowPos(w, &wx, &wy);
    glfwGetCursorPos(w, &x, &y);
    x += wx;
    y += wy;
}

bool maximized(GLFWwindow* w) { return glfwGetWindowAttrib(w, GLFW_MAXIMIZED) == GLFW_TRUE; }

void toggle_zoom(App& a) {
    if (maximized(a.win)) glfwRestoreWindow(a.win);
    else glfwMaximizeWindow(a.win);
}

}  // namespace

void request_close(App& a) {
    if (a.edits && a.edits->any_dirty()) {
        a.quit_requested = true;
        a.modal = "quit-unsaved";
        return;
    }
    glfwSetWindowShouldClose(a.win, GLFW_TRUE);
}

float window_buttons_width() { return 3 * 44 + 6; }

void draw_window_chrome(App& a) {
    ImGuiIO& io = ImGui::GetIO();
    ImDrawList* fg = ImGui::GetForegroundDrawList();
    ImVec2 wp = ImGui::GetMainViewport()->Pos, ws = ImGui::GetMainViewport()->Size;
    bool focused = glfwGetWindowAttrib(a.win, GLFW_FOCUSED) == GLFW_TRUE;
    bool zoomed = maximized(a.win);

    // Hairline around the window: there is no system frame to separate it from what is behind.
    if (!zoomed) fg->AddRect(wp, ImVec2(wp.x + ws.x, wp.y + ws.y), col(P.dark ? ImVec4(1, 1, 1, 0.10f) : ImVec4(0, 0, 0, 0.16f)));

    // Window buttons at the top right (Windows / Linux convention): minimise, maximise/restore, close.
    // Close turns red on hover; all respond on press.
    const float bw = 44, bh = 34, y0 = wp.y + 9;
    const float x0 = wp.x + ws.x - 6 - 3 * bw;
    bool modal = ImGui::IsPopupOpen("", ImGuiPopupFlags_AnyPopupId);
    const char* tips[3] = {"Minimize", zoomed ? "Restore" : "Maximize", "Close"};
    bool over_buttons = false;
    for (int i = 0; i < 3; i++) {
        ImRect r(ImVec2(x0 + i * bw, y0), ImVec2(x0 + (i + 1) * bw, y0 + bh));
        bool hov = r.Contains(io.MousePos) && !modal && !g_drag.moving && !g_drag.edges;
        over_buttons |= hov;
        bool held = hov && io.MouseDown[0];
        ImVec4 fill(0, 0, 0, 0), ink = focused ? P.text : P.dim;
        if (hov) {
            if (i == 2) { fill = held ? ImVec4(0.78f, 0.16f, 0.13f, 1) : ImVec4(0.91f, 0.07f, 0.14f, 1); ink = ImVec4(1, 1, 1, 1); }
            else fill = held ? ImGui::GetStyleColorVec4(ImGuiCol_FrameBgActive) : P.track;
        }
        if (fill.w > 0) fg->AddRectFilled(r.Min, r.Max, col(fill), 7);
        ImVec2 c((r.Min.x + r.Max.x) / 2, (r.Min.y + r.Max.y) / 2);
        ImU32 g = col(ink);
        float k = 5.0f;
        if (i == 0) {
            fg->AddLine(ImVec2(c.x - k, c.y), ImVec2(c.x + k, c.y), g, 1.2f);
        } else if (i == 1) {
            if (zoomed) {
                fg->AddRect(ImVec2(c.x - k, c.y - k + 2), ImVec2(c.x + k - 2, c.y + k), g, 1.5f, 0, 1.2f);
                fg->AddLine(ImVec2(c.x - k + 2, c.y - k), ImVec2(c.x + k, c.y - k), g, 1.2f);
                fg->AddLine(ImVec2(c.x + k, c.y - k), ImVec2(c.x + k, c.y + k - 2), g, 1.2f);
            } else {
                fg->AddRect(ImVec2(c.x - k, c.y - k), ImVec2(c.x + k, c.y + k), g, 1.5f, 0, 1.2f);
            }
        } else {
            fg->AddLine(ImVec2(c.x - k, c.y - k), ImVec2(c.x + k, c.y + k), g, 1.2f);
            fg->AddLine(ImVec2(c.x - k, c.y + k), ImVec2(c.x + k, c.y - k), g, 1.2f);
        }
        if (hov) {
            ImGui::SetTooltip("%s", tr(tips[i]));
            if (ImGui::IsMouseReleased(0)) {
                if (i == 0) glfwIconifyWindow(a.win);
                else if (i == 1) toggle_zoom(a);
                else request_close(a);
            }
        }
    }
    bool over_group = over_buttons;
    if (over_group) io.WantCaptureMouse = true;

    // Move / resize.
    ImVec2 m(io.MousePos.x - wp.x, io.MousePos.y - wp.y);
    int edge = None;
    if (!zoomed && !modal && m.x >= 0 && m.y >= 0 && m.x < ws.x && m.y < ws.y) {
        if (m.x < kEdge) edge |= L;
        if (m.x > ws.x - kEdge) edge |= R;
        if (m.y < kEdge) edge |= T;
        if (m.y > ws.y - kEdge) edge |= B;
    }
    int shown = g_drag.edges ? g_drag.edges : edge;
    if (shown) {
        bool h = shown & (L | R), v = shown & (T | B);
        bool nwse = ((shown & L) && (shown & T)) || ((shown & R) && (shown & B));
        ImGui::SetMouseCursor(h && v ? (nwse ? ImGuiMouseCursor_ResizeNWSE : ImGuiMouseCursor_ResizeNESW)
                                     : h ? ImGuiMouseCursor_ResizeEW : ImGuiMouseCursor_ResizeNS);
    }
    bool background = ImGui::IsWindowHovered(ImGuiHoveredFlags_ChildWindows) && !ImGui::IsAnyItemHovered() && !ImGui::IsAnyItemActive();
    if (ImGui::IsMouseClicked(0) && !over_group) {
        if (edge) {
            g_drag.edges = edge;
        } else if (m.y < kTitleZone && background && !modal) {
            if (ImGui::IsMouseDoubleClicked(0)) toggle_zoom(a);
            else if (!zoomed) g_drag.moving = true;
        }
        if (g_drag.edges || g_drag.moving) {
            screen_cursor(a.win, g_drag.sx, g_drag.sy);
            glfwGetWindowPos(a.win, &g_drag.wx, &g_drag.wy);
            glfwGetWindowSize(a.win, &g_drag.ww, &g_drag.wh);
        }
    }
    if (!io.MouseDown[0]) g_drag.moving = false, g_drag.edges = None;
    if (g_drag.moving || g_drag.edges) {
        io.WantCaptureMouse = true;
        double x, y;
        screen_cursor(a.win, x, y);
        int dx = int(x - g_drag.sx), dy = int(y - g_drag.sy);
        if (g_drag.moving) {
            glfwSetWindowPos(a.win, g_drag.wx + dx, g_drag.wy + dy);
        } else {
            int nx = g_drag.wx, ny = g_drag.wy, nw = g_drag.ww, nh = g_drag.wh;
            const int minw = 720, minh = 480;
            if (g_drag.edges & R) nw = std::max(minw, g_drag.ww + dx);
            if (g_drag.edges & B) nh = std::max(minh, g_drag.wh + dy);
            if (g_drag.edges & L) { nw = std::max(minw, g_drag.ww - dx); nx = g_drag.wx + g_drag.ww - nw; }
            if (g_drag.edges & T) { nh = std::max(minh, g_drag.wh - dy); ny = g_drag.wy + g_drag.wh - nh; }
            if (nx != g_drag.wx || ny != g_drag.wy) glfwSetWindowPos(a.win, nx, ny);
            glfwSetWindowSize(a.win, nw, nh);
        }
    }
}

}  // namespace s3v::ui
