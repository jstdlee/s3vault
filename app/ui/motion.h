// Motion for an immediate-mode UI: values that ease toward a target, retargeting from wherever they are
// (so a second click mid-animation never jumps). Curves and durations follow the animate-it rules:
// strong ease-out for things appearing, strong ease-in-out for things moving on screen, all under 300 ms,
// and nothing on keyboard-driven or 100+-times-a-day actions.
#pragma once
#include "imgui.h"

namespace s3v::ui::motion {

// "system" (desktop setting), "full" or "reduced". Reduced keeps fades and drops movement.
void configure(const char* setting);
bool reduced();

void frame_begin();
// True while anything is mid-animation: the main loop then renders every frame instead of waiting for input.
bool animating();
void keep_alive();  // for animations that are not tweens (e.g. a highlight that fades over time)

float ease_out(float t);     // cubic-bezier(0.23, 1, 0.32, 1)
float ease_in_out(float t);  // cubic-bezier(0.77, 0, 0.175, 1)

// Eases toward `target` over `dur` seconds. The first call returns `target` (no animation on first show).
float tween(ImGuiID id, float target, float dur, float (*ease)(float) = ease_in_out, bool snap = false);  // snap: jump there
// Progress 0 → 1 (eased) since `id` started being drawn; restarts after a frame without a call.
float appear(ImGuiID id, float dur);
// Movement amount: `px`, or 0 under reduced motion.
inline float move(float px) { return reduced() ? 0.0f : px; }

constexpr float kFast = 0.16f;   // segment pill, sidebar selection
constexpr float kSheet = 0.20f;  // sheets, toasts

}  // namespace s3v::ui::motion
