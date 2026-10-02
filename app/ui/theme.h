// Visual language: macOS-like, after the "Magpie" preferences style (soft grey window, white rounded cards,
// grey one-line explanations, segmented pills). Every colour comes from the palette; light and dark share layout.
#pragma once
#include <functional>
#include <string>
#include <vector>

#include "imgui.h"

namespace s3v::ui {

struct Palette {
    ImVec4 bg;        // window / toolbar
    ImVec4 sidebar;   // source list
    ImVec4 card;      // cards, list background, sheets
    ImVec4 border;    // 1 px outlines
    ImVec4 divider;   // lines between rows
    ImVec4 text, dim, faint;
    ImVec4 track;     // fields, segmented-control track
    ImVec4 pill;      // chosen segment
    ImVec4 hover;     // row hover
    ImVec4 select;    // row selection (accent tint)
    ImVec4 accent, accent_hover, on_accent;
    ImVec4 red, orange, green, blue, purple, grey, teal, yellow;
    ImVec4 folder;
    bool dark = false;
};
extern Palette P;
extern ImFont* g_mono;  // monospaced font for code, text preview, editor (may be null → default)

bool system_prefers_dark();
void apply_theme(bool dark);
ImU32 col(const ImVec4& c, float alpha = 1.0f);

// ---- small widgets -------------------------------------------------------------------------------
enum class Btn { Secondary, Primary, Destructive, Plain };
bool button(const char* label, Btn kind = Btn::Secondary, ImVec2 size = ImVec2(0, 0), bool enabled = true);
// Borderless toolbar glyph (28×28) with tooltip; `on` draws it as selected.
bool icon_button(const char* icon, const char* tip, bool on = false, bool enabled = true, float size = 30);
void tip(const std::string& text);
void title_text(const char* text, float scale = 1.25f);  // larger heading (no bold: size, not weight)
void small_dim(const char* fmt, ...);
// `dy`: extra vertical offset, e.g. FramePadding.y after AlignTextToFramePadding().
void status_dot(const ImVec4& c, float r = 4.0f, float dy = 0.0f);
// A status value: coloured dot + text in the normal text colour (coloured text is too faint on white for AA).
void status_text(const ImVec4& c, const char* text);
// Keyboard focus ring (3 px, accent at 50 %) around the last item, for custom-drawn controls.
void focus_ring(float rounding = 6.0f);
void badge(const std::string& text, const ImVec4& bg, const ImVec4& fg);
bool search_field(const char* id, char* buf, size_t n, float width, const char* hint = "Search");
void spinner(float radius, const ImVec4& c);
void empty_state(const char* icon, const char* title, const char* line);
// Thin rounded progress bar.
void progress(float f, float width, float height = 5);
// Page header in the 52 px toolbar strip: title + grey subtitle; returns the y where content starts.
float page_header(const char* title, const char* subtitle = nullptr);
// Centred column of a given max width (for setup / lock pages).
void center_column_begin(float width, float y_frac = 0.18f);
void center_column_end();

// Type icon + its tint (folder blue, PDF red, image purple…).
const char* type_icon(const std::string& name, bool dir, bool open = false);
ImVec4 type_color(const std::string& name, bool dir);
// Status colour for sync statuses ("Synced", "Pending", …).
ImVec4 status_color(const std::string& status);

// ---- sheets (Apple-style modal dialogs) ----------------------------------------------------------
// The sheet `id` is shown while `*current == id`; returns true while it is open (call sheet_end()).
bool sheet_begin(std::string& current, const char* id, float width = 460);
void sheet_end();
void sheet_title(const char* icon, const ImVec4& icon_col, const char* title, const char* subtitle = nullptr);
// Right-aligned button row: returns 1 for primary, 2 for secondary/cancel, 0 none. Enter/Escape map to them.
int sheet_buttons(const char* primary, const char* cancel = "Cancel", bool primary_enabled = true, bool destructive = false,
                  const char* extra = nullptr, int* extra_clicked = nullptr);
void sheet_close(std::string& current);
// Labelled field inside a sheet (label above, full width).
bool sheet_field(const char* label, char* buf, size_t n, const char* hint = "", bool password = false, bool focus = false);

// ---- preference rows (cards) ---------------------------------------------------------------------
namespace prefs {
extern bool g_dirty;
void page_begin(float max_width = 760);
void page_end();
// `caps` false for data such as folder paths, which must keep their case.
void section(const char* title, bool caps = true);
void card_begin();
void card_end();
// A row with a title/description on the left; the callback draws the control (right-aligned, width w).
void row(const char* title, const char* desc, float w, const std::function<void()>& control, const char* more = nullptr);
bool choice(const char* title, const char* desc, int* v, const std::vector<std::string>& labels, const char* more = nullptr);
bool toggle(const char* title, const char* desc, bool* b, const char* more = nullptr);
bool text(const char* title, const char* desc, std::string& value, float w = 300, const char* hint = "", bool password = false);
bool number(const char* title, const char* desc, int* v, int lo, int hi, float w = 130);
bool action(const char* title, const char* desc, const char* button_label, Btn kind = Btn::Secondary, bool enabled = true);
void info(const char* title, const char* desc, const char* value, const ImVec4* value_col = nullptr);
float seg_width(const std::vector<std::string>& labels);
bool seg(const char* id, int* v, const std::vector<std::string>& labels);
}  // namespace prefs

}  // namespace s3v::ui
