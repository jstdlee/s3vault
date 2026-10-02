#include "motion.h"

#include <cmath>
#include <cstring>
#include <string>
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#else
#include "util/strings.h"
#include "util/subprocess.h"
#endif

namespace s3v::ui::motion {

namespace {

bool g_reduced = false;
bool g_animating = false, g_animating_next = false;
int g_frame = 0;

struct Tween {
    float from = 0, to = 0, cur = 0;
    double start = 0;
};
struct Appear {
    double start = 0;
    int last = -10;
};

// y of a cubic bezier with control points (x1,y1) (x2,y2) at x (Newton, then bisection).
float bezier(float x1, float y1, float x2, float y2, float x) {
    if (x <= 0) return 0;
    if (x >= 1) return 1;
    auto bx = [&](float t) { return ((1 - 3 * x2 + 3 * x1) * t + (3 * x2 - 6 * x1)) * t * t + 3 * x1 * t; };
    auto by = [&](float t) { return ((1 - 3 * y2 + 3 * y1) * t + (3 * y2 - 6 * y1)) * t * t + 3 * y1 * t; };
    auto dx = [&](float t) { return 3 * (1 - 3 * x2 + 3 * x1) * t * t + 2 * (3 * x2 - 6 * x1) * t + 3 * x1; };
    float t = x;
    for (int i = 0; i < 8; i++) {
        float e = bx(t) - x, d = dx(t);
        if (std::fabs(e) < 1e-4f) return by(t);
        if (std::fabs(d) < 1e-6f) break;
        t -= e / d;
    }
    float lo = 0, hi = 1;
    t = x;
    for (int i = 0; i < 30; i++) {
        float v = bx(t);
        if (std::fabs(v - x) < 1e-4f) break;
        (v < x ? lo : hi) = t;
        t = (lo + hi) / 2;
    }
    return by(t);
}

bool system_reduced() {
#ifdef _WIN32
    BOOL on = TRUE;
    return SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &on, 0) && !on;
#else
    std::string out;
    if (run_capture({"gsettings", "get", "org.gnome.desktop.interface", "enable-animations"}, "", &out, nullptr, 256, 1500) == 0)
        return trim(out) == "false";
    return false;
#endif
}

std::unordered_map<ImGuiID, Tween>& tweens() {
    static std::unordered_map<ImGuiID, Tween> m;
    return m;
}
std::unordered_map<ImGuiID, Appear>& appears() {
    static std::unordered_map<ImGuiID, Appear> m;
    return m;
}

}  // namespace

void configure(const char* setting) {
    static std::string last;
    static bool sys = false;
    if (last != setting) {
        last = setting;
        if (!strcmp(setting, "system")) sys = system_reduced();
    }
    g_reduced = !strcmp(setting, "reduced") || (!strcmp(setting, "system") && sys);
}

bool reduced() { return g_reduced; }

void frame_begin() {
    g_animating = g_animating_next;
    g_animating_next = false;
    g_frame++;
}

bool animating() { return g_animating || g_animating_next; }
void keep_alive() { g_animating_next = true; }

float ease_out(float t) { return bezier(0.23f, 1.0f, 0.32f, 1.0f, t); }
float ease_in_out(float t) { return bezier(0.77f, 0.0f, 0.175f, 1.0f, t); }

float tween(ImGuiID id, float target, float dur, float (*ease)(float), bool snap) {
    double now = ImGui::GetTime();
    auto [it, fresh] = tweens().try_emplace(id);
    Tween& w = it->second;
    if (fresh || g_reduced || snap) {
        w.from = w.to = w.cur = target;
        return target;
    }
    if (target != w.to) {
        w.from = w.cur;
        w.to = target;
        w.start = now;
    }
    float t = dur > 0 ? float((now - w.start) / dur) : 1.0f;
    if (t >= 1) {
        w.cur = w.to;
    } else {
        w.cur = w.from + (w.to - w.from) * ease(t);
        g_animating_next = true;
    }
    return w.cur;
}

float appear(ImGuiID id, float dur) {
    double now = ImGui::GetTime();
    Appear& a = appears()[id];
    if (a.last < g_frame - 1) a.start = now;
    a.last = g_frame;
    float t = dur > 0 ? float((now - a.start) / dur) : 1.0f;
    if (t >= 1) return 1;
    g_animating_next = true;
    return ease_out(t);
}

}  // namespace s3v::ui::motion
