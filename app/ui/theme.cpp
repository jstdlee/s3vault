#include "theme.h"

#include <GLFW/glfw3.h>

#include <algorithm>
#include <cmath>
#include <cstdarg>
#include <cstring>

#include "IconsFontAwesome6.h"
#include "imgui_internal.h"
#include "preview/preview.h"
#include "util/strings.h"
#include "util/subprocess.h"

namespace s3v::ui {

Palette P;
ImFont* g_mono = nullptr;

static ImVec4 hex(unsigned v, float a = 1.0f) {
    return ImVec4(float((v >> 16) & 255) / 255.0f, float((v >> 8) & 255) / 255.0f, float(v & 255) / 255.0f, a);
}

ImU32 col(const ImVec4& c, float alpha) { return ImGui::GetColorU32(ImVec4(c.x, c.y, c.z, c.w * alpha)); }

bool system_prefers_dark() {
    std::string out;
    if (run_capture({"gsettings", "get", "org.gnome.desktop.interface", "color-scheme"}, "", &out, nullptr, 4096, 2000) == 0)
        return out.find("dark") != std::string::npos;
    return false;
}

void apply_theme(bool dark) {
    if (dark) {
        P.bg = hex(0x1c1c1f); P.sidebar = hex(0x232327); P.card = hex(0x252528); P.border = hex(0x303034);
        P.divider = hex(0x2c2c30); P.text = hex(0xe8e8ec); P.dim = hex(0x8e8e96); P.faint = hex(0x5c5c63);
        P.track = hex(0x2e2e33); P.pill = hex(0x3a3a40); P.hover = hex(0xffffff, 0.045f); P.select = hex(0x0a84ff, 0.30f);
        P.accent = hex(0x0a84ff); P.accent_hover = hex(0x3a9bff); P.on_accent = hex(0xffffff);
        P.red = hex(0xff453a); P.orange = hex(0xff9f0a); P.green = hex(0x30d158); P.blue = hex(0x0a84ff);
        P.purple = hex(0xbf5af2); P.grey = hex(0x98989d); P.teal = hex(0x64d2ff); P.yellow = hex(0xffd60a);
        P.folder = hex(0x5fb2f6);
    } else {
        P.bg = hex(0xf4f4f6); P.sidebar = hex(0xebebef); P.card = hex(0xffffff); P.border = hex(0xe3e3e8);
        P.divider = hex(0xececf0); P.text = hex(0x212126); P.dim = hex(0x737379);  // Magpie measured #85858d; darkened for WCAG AA P.faint = hex(0xb4b4ba);
        P.track = hex(0xf1f1f4); P.pill = hex(0xffffff); P.hover = hex(0x000000, 0.035f); P.select = hex(0x007aff, 0.16f);
        P.accent = hex(0x007aff); P.accent_hover = hex(0x2b8fff); P.on_accent = hex(0xffffff);
        P.red = hex(0xff3b30); P.orange = hex(0xff9500); P.green = hex(0x28cd41); P.blue = hex(0x007aff);
        P.purple = hex(0xaf52de); P.grey = hex(0x8e8e93); P.teal = hex(0x32ade6); P.yellow = hex(0xffcc00);
        P.folder = hex(0x3d9cf5);
    }
    P.dark = dark;

    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowPadding = ImVec2(0, 0);
    s.FramePadding = ImVec2(9, 5);
    s.ItemSpacing = ImVec2(8, 6);
    s.ItemInnerSpacing = ImVec2(6, 4);
    s.CellPadding = ImVec2(8, 5);
    s.IndentSpacing = 18;
    s.ScrollbarSize = 10;
    s.GrabMinSize = 10;
    s.WindowBorderSize = 0;
    s.ChildBorderSize = 1;
    s.PopupBorderSize = 1;
    s.FrameBorderSize = 0;
    s.WindowRounding = 12;
    s.ChildRounding = 10;
    s.FrameRounding = 6;
    s.PopupRounding = 10;
    s.ScrollbarRounding = 8;
    s.GrabRounding = 6;
    s.TabRounding = 6;
    s.TabBorderSize = 0;
    s.TreeLinesFlags = ImGuiTreeNodeFlags_DrawLinesNone;
    s.SelectableTextAlign = ImVec2(0, 0.5f);

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text] = P.text;
    c[ImGuiCol_TextDisabled] = P.dim;
    c[ImGuiCol_WindowBg] = P.bg;
    c[ImGuiCol_ChildBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_PopupBg] = P.card;
    c[ImGuiCol_Border] = P.border;
    c[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg] = P.track;
    c[ImGuiCol_FrameBgHovered] = dark ? hex(0x36363c) : hex(0xe9e9ee);
    c[ImGuiCol_FrameBgActive] = dark ? hex(0x3a3a40) : hex(0xe4e4ea);
    c[ImGuiCol_TitleBg] = P.bg;
    c[ImGuiCol_TitleBgActive] = P.bg;
    c[ImGuiCol_TitleBgCollapsed] = P.bg;
    c[ImGuiCol_MenuBarBg] = P.bg;
    c[ImGuiCol_ScrollbarBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab] = ImVec4(P.dim.x, P.dim.y, P.dim.z, 0.35f);
    c[ImGuiCol_ScrollbarGrabHovered] = ImVec4(P.dim.x, P.dim.y, P.dim.z, 0.55f);
    c[ImGuiCol_ScrollbarGrabActive] = ImVec4(P.dim.x, P.dim.y, P.dim.z, 0.7f);
    c[ImGuiCol_CheckMark] = P.on_accent;
    c[ImGuiCol_SliderGrab] = P.accent;
    c[ImGuiCol_SliderGrabActive] = P.accent_hover;
    c[ImGuiCol_Button] = P.track;
    c[ImGuiCol_ButtonHovered] = c[ImGuiCol_FrameBgHovered];
    c[ImGuiCol_ButtonActive] = c[ImGuiCol_FrameBgActive];
    c[ImGuiCol_Header] = P.select;
    c[ImGuiCol_HeaderHovered] = P.hover;
    c[ImGuiCol_HeaderActive] = P.select;
    c[ImGuiCol_Separator] = P.divider;
    c[ImGuiCol_SeparatorHovered] = P.accent;
    c[ImGuiCol_SeparatorActive] = P.accent;
    c[ImGuiCol_ResizeGrip] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ResizeGripHovered] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ResizeGripActive] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_Tab] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TabHovered] = P.hover;
    c[ImGuiCol_TabSelected] = P.card;
    c[ImGuiCol_TabSelectedOverline] = P.accent;
    c[ImGuiCol_TabDimmed] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TabDimmedSelected] = P.card;
    c[ImGuiCol_PlotHistogram] = P.accent;
    c[ImGuiCol_TableHeaderBg] = P.card;
    c[ImGuiCol_TableBorderStrong] = P.divider;
    c[ImGuiCol_TableBorderLight] = P.divider;
    c[ImGuiCol_TableRowBg] = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt] = dark ? hex(0xffffff, 0.018f) : hex(0x000000, 0.018f);
    c[ImGuiCol_TextSelectedBg] = ImVec4(P.accent.x, P.accent.y, P.accent.z, 0.30f);
    c[ImGuiCol_NavCursor] = ImVec4(P.accent.x, P.accent.y, P.accent.z, 0.6f);
    c[ImGuiCol_ModalWindowDimBg] = dark ? hex(0x000000, 0.45f) : hex(0x000000, 0.22f);
    c[ImGuiCol_DragDropTarget] = P.accent;
}

// ---------------------------------------------------------------------------------------------------
// widgets

void tip(const std::string& text) {
    if (!text.empty() && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled | ImGuiHoveredFlags_DelayNormal))
        ImGui::SetTooltip("%s", text.c_str());
}

bool button(const char* label, Btn kind, ImVec2 size, bool enabled) {
    ImVec2 ts = ImGui::CalcTextSize(label, nullptr, true);
    float h = size.y > 0 ? size.y : ImGui::GetFrameHeight();
    float w = size.x > 0 ? size.x : ts.x + 28;
    ImGui::BeginDisabled(!enabled);
    ImVec2 p = ImGui::GetCursorScreenPos();
    bool pressed = ImGui::InvisibleButton(label, ImVec2(w, h));
    focus_ring(6.0f);
    bool hov = ImGui::IsItemHovered(), act = ImGui::IsItemActive();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float alpha = enabled ? 1.0f : 0.45f;
    ImVec4 bg, fg;
    switch (kind) {
        case Btn::Primary: bg = hov ? P.accent_hover : P.accent; fg = P.on_accent; break;
        case Btn::Destructive: bg = hov ? P.red : P.track; fg = hov ? P.on_accent : P.red; break;
        case Btn::Plain: bg = hov ? P.hover : ImVec4(0, 0, 0, 0); fg = P.accent; break;
        default: bg = hov ? ImGui::GetStyleColorVec4(ImGuiCol_FrameBgHovered) : P.track; fg = P.text; break;
    }
    if (act && kind != Btn::Plain) bg = ImVec4(bg.x * 0.92f, bg.y * 0.92f, bg.z * 0.92f, bg.w);
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), col(bg, alpha), 6.0f);
    if (kind == Btn::Secondary) dl->AddRect(p, ImVec2(p.x + w, p.y + h), col(P.border, alpha), 6.0f);
    dl->AddText(ImVec2(p.x + (w - ts.x) / 2, p.y + (h - ts.y) / 2), col(fg, alpha), label, ImGui::FindRenderedTextEnd(label));
    ImGui::EndDisabled();
    return pressed && enabled;
}

bool icon_button(const char* icon, const char* tip_text, bool on, bool enabled, float size) {
    ImGui::BeginDisabled(!enabled);
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::PushID(icon);
    ImGui::PushID(tip_text ? tip_text : "");
    bool pressed = ImGui::InvisibleButton("##ib", ImVec2(size, size));
    ImGui::PopID();
    ImGui::PopID();
    focus_ring(7.0f);
    bool hov = ImGui::IsItemHovered();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (on) dl->AddRectFilled(p, ImVec2(p.x + size, p.y + size), col(P.select), 7.0f);
    else if (hov && enabled) dl->AddRectFilled(p, ImVec2(p.x + size, p.y + size), col(P.track), 7.0f);
    ImVec2 ts = ImGui::CalcTextSize(icon);
    ImVec4 fg = on ? P.accent : hov ? P.text : P.dim;
    dl->AddText(ImVec2(p.x + (size - ts.x) / 2, p.y + (size - ts.y) / 2), col(fg, enabled ? 1.0f : 0.4f), icon);
    if (tip_text) tip(tip_text);
    ImGui::EndDisabled();
    return pressed && enabled;
}

void title_text(const char* text, float scale) {
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * scale);
    ImGui::TextUnformatted(text);
    ImGui::PopFont();
}

void small_dim(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 0.86f);
    ImGui::TextDisabled("%s", buf);
    ImGui::PopFont();
}

void status_dot(const ImVec4& c, float r, float dy) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    float h = ImGui::GetTextLineHeight();
    ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(p.x + r, p.y + dy + h / 2), r, col(c), 16);
    ImGui::Dummy(ImVec2(r * 2, h));
}

void status_text(const ImVec4& c, const char* text) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    float h = ImGui::GetTextLineHeight(), r = 3.5f;
    ImGui::GetWindowDrawList()->AddCircleFilled(ImVec2(p.x + r, p.y + h / 2), r, col(c), 16);
    ImGui::SetCursorScreenPos(ImVec2(p.x + r * 2 + 7, p.y));
    ImGui::TextUnformatted(text);
}

void focus_ring(float rounding) {
    if (!ImGui::IsItemFocused() || !ImGui::GetIO().NavVisible) return;
    ImVec2 a = ImGui::GetItemRectMin(), b = ImGui::GetItemRectMax();
    ImGui::GetWindowDrawList()->AddRect(ImVec2(a.x - 2.5f, a.y - 2.5f), ImVec2(b.x + 2.5f, b.y + 2.5f), col(P.accent, 0.5f), rounding + 2.5f, 0, 3.0f);
}

void badge(const std::string& text, const ImVec4& bg, const ImVec4& fg) {
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 0.8f);
    ImVec2 ts = ImGui::CalcTextSize(text.c_str());
    ImVec2 p = ImGui::GetCursorScreenPos();
    float h = ts.y + 4, w = std::max(h, ts.x + 12);
    float y = p.y + (ImGui::GetTextLineHeight() * 1.18f - h) / 2;
    ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(p.x, y), ImVec2(p.x + w, y + h), col(bg), h / 2);
    ImGui::GetWindowDrawList()->AddText(ImVec2(p.x + (w - ts.x) / 2, y + 2), col(fg), text.c_str());
    ImGui::PopFont();
    ImGui::Dummy(ImVec2(w, ImGui::GetTextLineHeight()));
}

bool search_field(const char* id, char* buf, size_t n, float width, const char* hint) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    float h = ImGui::GetFrameHeight();
    float icon_w = ImGui::CalcTextSize(ICON_FA_MAGNIFYING_GLASS).x;
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10 + icon_w + 7, ImGui::GetStyle().FramePadding.y));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, h / 2);
    ImGui::SetNextItemWidth(width);
    bool ch = ImGui::InputTextWithHint(id, hint, buf, n);
    ImGui::PopStyleVar(2);
    ImVec2 ts = ImGui::CalcTextSize(ICON_FA_MAGNIFYING_GLASS);
    ImGui::GetWindowDrawList()->AddText(ImVec2(p.x + 10, p.y + (h - ts.y) / 2), col(P.dim), ICON_FA_MAGNIFYING_GLASS);
    if (buf[0]) {  // clear button
        ImVec2 save = ImGui::GetCursorScreenPos();
        ImGui::SetCursorScreenPos(ImVec2(p.x + width - h, p.y));
        ImGui::PushID(id);
        if (ImGui::InvisibleButton("##clear", ImVec2(h, h))) { buf[0] = 0; ch = true; }
        ImGui::PopID();
        ImVec2 xs = ImGui::CalcTextSize(ICON_FA_CIRCLE_XMARK);
        ImGui::GetWindowDrawList()->AddText(ImVec2(p.x + width - h + (h - xs.x) / 2, p.y + (h - xs.y) / 2),
                                            col(ImGui::IsItemHovered() ? P.text : P.faint), ICON_FA_CIRCLE_XMARK);
        ImGui::SetCursorScreenPos(save);
    }
    return ch;
}

void spinner(float r, const ImVec4& c) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    float t = float(ImGui::GetTime()) * 6.0f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 ctr(p.x + r, p.y + ImGui::GetTextLineHeight() / 2);
    for (int i = 0; i < 8; i++) {
        float a = t + float(i) * 6.2831853f / 8;
        float alpha = 0.15f + 0.85f * float(i) / 8;
        dl->AddLine(ImVec2(ctr.x + cosf(a) * r * 0.45f, ctr.y + sinf(a) * r * 0.45f), ImVec2(ctr.x + cosf(a) * r, ctr.y + sinf(a) * r),
                    col(c, alpha), 2.0f);
    }
    ImGui::Dummy(ImVec2(r * 2, ImGui::GetTextLineHeight()));
}

void empty_state(const char* icon, const char* title, const char* line) {
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float base = ImGui::GetStyle().FontSizeBase;
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + std::max(20.0f, avail.y * 0.28f));
    auto centered = [&](const char* t, float scale, const ImVec4& c) {
        ImGui::PushFont(nullptr, base * scale);
        float w = ImGui::CalcTextSize(t).x;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + std::max(0.0f, (avail.x - w) / 2));
        ImGui::TextColored(c, "%s", t);
        ImGui::PopFont();
    };
    float x0 = ImGui::GetCursorPosX();
    centered(icon, 3.0f, P.faint);
    ImGui::SetCursorPosX(x0);
    ImGui::Dummy(ImVec2(0, 4));
    ImGui::SetCursorPosX(x0);
    centered(title, 1.15f, P.text);
    ImGui::SetCursorPosX(x0);
    centered(line, 0.92f, P.dim);
}

void progress(float f, float width, float height) {
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float y = p.y + (ImGui::GetTextLineHeight() - height) / 2;
    dl->AddRectFilled(ImVec2(p.x, y), ImVec2(p.x + width, y + height), col(P.track), height / 2);
    f = std::clamp(f, 0.0f, 1.0f);
    if (f > 0) dl->AddRectFilled(ImVec2(p.x, y), ImVec2(p.x + std::max(height, width * f), y + height), col(P.accent), height / 2);
    ImGui::Dummy(ImVec2(width, ImGui::GetTextLineHeight()));
}

float page_header(const char* title, const char* subtitle) {
    float top = 52;
    ImGui::SetCursorPos(ImVec2(20, (top - ImGui::GetTextLineHeight() * 1.18f) / 2));
    title_text(title, 1.18f);
    if (subtitle && *subtitle) {
        ImGui::SameLine(0, 12);
        ImGui::SetCursorPosY((top - ImGui::GetTextLineHeight()) / 2 + 1);
        small_dim("%s", subtitle);
    }
    ImVec2 wp = ImGui::GetWindowPos();
    ImGui::GetWindowDrawList()->AddLine(ImVec2(wp.x, wp.y + top - 1), ImVec2(wp.x + ImGui::GetWindowWidth(), wp.y + top - 1), col(P.divider));
    return top;
}

void center_column_begin(float width, float y_frac) {
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float w = std::min(width, avail.x - 32);
    ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + (avail.x - w) / 2, ImGui::GetCursorPosY() + avail.y * y_frac));
    ImGui::BeginChild("##col", ImVec2(w, 0), ImGuiChildFlags_AutoResizeY, ImGuiWindowFlags_NoScrollbar);
}

void center_column_end() { ImGui::EndChild(); }

const char* type_icon(const std::string& name, bool dir, bool open) {
    if (dir) return open ? ICON_FA_FOLDER_OPEN : ICON_FA_FOLDER;
    std::string t = file_type_label(name);
    if (t == "Text") return ICON_FA_FILE_LINES;
    if (t == "Code") return ICON_FA_FILE_CODE;
    if (t == "Image") return ICON_FA_FILE_IMAGE;
    if (t == "PDF") return ICON_FA_FILE_PDF;
    if (t == "Audio") return ICON_FA_FILE_AUDIO;
    if (t == "Video") return ICON_FA_FILE_VIDEO;
    if (t == "Archive") return ICON_FA_FILE_ZIPPER;
    if (t == "Document") return ICON_FA_FILE_WORD;
    return ICON_FA_FILE;
}

ImVec4 type_color(const std::string& name, bool dir) {
    if (dir) return P.folder;
    std::string t = file_type_label(name);
    if (t == "Image") return P.purple;
    if (t == "PDF") return P.red;
    if (t == "Code") return P.teal;
    if (t == "Audio") return hex(0xff2d55);
    if (t == "Video") return P.orange;
    if (t == "Archive") return P.yellow;
    if (t == "Document") return P.blue;
    return P.grey;
}

ImVec4 status_color(const std::string& s) {
    if (s == "Synced") return P.green;
    if (s == "Pending") return P.blue;
    if (s == "Conflict") return P.orange;
    if (s == "Locked") return P.yellow;
    if (s == "Paused") return P.grey;
    return P.faint;
}

// ---------------------------------------------------------------------------------------------------
// sheets

static std::string g_sheet_stack;  // id of the sheet being drawn

bool sheet_begin(std::string& current, const char* id, float width) {
    std::string pid = std::string("##sheet_") + id;
    bool want = current == id;
    if (want && !ImGui::IsPopupOpen(pid.c_str())) ImGui::OpenPopup(pid.c_str());
    if (!ImGui::IsPopupOpen(pid.c_str())) return false;
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + vp->WorkSize.x / 2, vp->WorkPos.y + vp->WorkSize.y * 0.42f), ImGuiCond_Always,
                            ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(std::min(width, vp->WorkSize.x - 40), 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(22, 20));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8, 8));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, P.card);
    bool open = ImGui::BeginPopupModal(pid.c_str(), nullptr,
                                       ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                                           ImGuiWindowFlags_AlwaysAutoResize);
    ImGui::PopStyleColor();
    if (!open) {
        ImGui::PopStyleVar(2);
        return false;
    }
    if (!want) {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        ImGui::PopStyleVar(2);
        return false;
    }
    g_sheet_stack = id;
    return true;
}

void sheet_end() {
    ImGui::EndPopup();
    ImGui::PopStyleVar(2);
}

void sheet_close(std::string& current) {
    current.clear();
    ImGui::CloseCurrentPopup();
}

void sheet_title(const char* icon, const ImVec4& icon_col, const char* title, const char* subtitle) {
    if (icon) {
        ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 2.0f);
        ImGui::TextColored(icon_col, "%s", icon);
        ImGui::PopFont();
    }
    title_text(title, 1.2f);
    if (subtitle && *subtitle) {
        ImGui::PushStyleColor(ImGuiCol_Text, P.dim);
        ImGui::TextWrapped("%s", subtitle);
        ImGui::PopStyleColor();
    }
    ImGui::Dummy(ImVec2(0, 4));
}

int sheet_buttons(const char* primary, const char* cancel, bool primary_enabled, bool destructive, const char* extra, int* extra_clicked) {
    ImGui::Dummy(ImVec2(0, 6));
    float pw = primary ? ImGui::CalcTextSize(primary).x + 32 : 0;
    float cw = cancel ? ImGui::CalcTextSize(cancel).x + 32 : 0;
    float right = ImGui::GetContentRegionAvail().x;
    int r = 0;
    if (extra) {
        if (button(extra, Btn::Plain)) {
            if (extra_clicked) *extra_clicked = 1;
        }
        ImGui::SameLine();
    }
    float x = ImGui::GetCursorPosX();
    float start = std::max(x, ImGui::GetWindowContentRegionMin().x + right - pw - cw - (primary && cancel ? 8 : 0));
    ImGui::SetCursorPosX(start);
    if (cancel) {
        if (button(cancel, Btn::Secondary, ImVec2(cw, 0))) r = 2;
        if (primary) ImGui::SameLine();
    }
    if (primary) {
        if (button(primary, destructive ? Btn::Destructive : Btn::Primary, ImVec2(pw, 0), primary_enabled)) r = 1;
    }
    bool typing_multiline = false;
    if (r == 0 && !typing_multiline) {
        if (primary && primary_enabled && (ImGui::IsKeyPressed(ImGuiKey_Enter) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter))) r = 1;
        if (cancel && ImGui::IsKeyPressed(ImGuiKey_Escape)) r = 2;
    }
    return r;
}

bool sheet_field(const char* label, char* buf, size_t n, const char* hint, bool password, bool focus) {
    small_dim("%s", label);
    ImGui::SetNextItemWidth(-1);
    if (focus && ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
    return ImGui::InputTextWithHint((std::string("##") + label).c_str(), hint, buf, n, password ? ImGuiInputTextFlags_Password : 0);
}

// ---------------------------------------------------------------------------------------------------
// preference rows

namespace prefs {

bool g_dirty = false;
static const float kPad = 14;
struct Card {
    ImVec2 p0;
    float x0 = 0, w = 0;
    bool first = true;
};
static Card g_card;

void page_begin(float max_width) {
    g_card.w = std::min(ImGui::GetContentRegionAvail().x - 32, max_width);
    g_card.x0 = std::max(16.0f, (ImGui::GetContentRegionAvail().x - g_card.w) / 2);
    g_dirty = false;
}

void page_end() { ImGui::Dummy(ImVec2(0, 24)); }

void section(const char* title, bool caps) {
    ImGui::Dummy(ImVec2(0, 12));
    std::string up;
    for (const char* s = title; *s; s++) up += caps ? char(toupper(static_cast<unsigned char>(*s))) : *s;
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 0.8f);
    ImGui::SetCursorPosX(g_card.x0 + 3);
    ImGui::TextDisabled("%s", up.c_str());
    ImGui::PopFont();
    ImGui::Dummy(ImVec2(0, 1));
}

void card_begin() {
    g_card.first = true;
    ImGui::SetCursorPosX(g_card.x0);
    g_card.p0 = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->ChannelsSplit(2);
    dl->ChannelsSetCurrent(1);
}

void card_end() {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p1(g_card.p0.x + g_card.w, ImGui::GetCursorScreenPos().y);
    dl->ChannelsSetCurrent(0);
    dl->AddRectFilled(g_card.p0, p1, col(P.card), 10.0f);
    dl->AddRect(g_card.p0, p1, col(P.border), 10.0f);
    dl->ChannelsMerge();
}

void row(const char* title, const char* desc, float ctrl_w, const std::function<void()>& control, const char* more) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImGui::SetCursorPosX(g_card.x0);
    ImVec2 top = ImGui::GetCursorScreenPos();
    float lh = ImGui::GetTextLineHeight(), small = ImGui::GetStyle().FontSizeBase * 0.86f;
    bool has_desc = desc && *desc;
    float h = kPad * 2 + lh + (has_desc ? small + 4 : 0);
    if (!g_card.first) dl->AddLine(ImVec2(top.x + kPad, top.y), ImVec2(top.x + g_card.w - 1, top.y), col(P.divider));
    g_card.first = false;
    float text_w = g_card.w - kPad * 3 - ctrl_w;
    ImGui::SetCursorScreenPos(ImVec2(top.x + kPad, top.y + kPad));
    ImGui::TextUnformatted(title);
    if (has_desc) {
        ImGui::SetCursorScreenPos(ImVec2(top.x + kPad, top.y + kPad + lh + 3));
        ImGui::PushFont(nullptr, small);
        std::string d = desc;
        bool cut = false;
        while (d.size() > 8 && ImGui::CalcTextSize(d.c_str()).x > text_w) {
            size_t k = d.size() - 1;
            while (k > 0 && (static_cast<unsigned char>(d[k]) & 0xC0) == 0x80) k--;
            d.resize(k);
            cut = true;
        }
        if (cut) d += "…";
        ImGui::TextDisabled("%s", d.c_str());
        ImGui::PopFont();
        if (cut || more) tip(more ? std::string(desc) + "\n" + more : std::string(desc));
    } else if (more) {
        tip(more);
    }
    ImGui::SetCursorScreenPos(ImVec2(top.x + g_card.w - kPad - ctrl_w, top.y + (h - ImGui::GetFrameHeight()) / 2));
    ImGui::PushID(title);
    ImGui::PushID(desc ? desc : "");
    control();
    ImGui::PopID();
    ImGui::PopID();
    ImGui::SetCursorScreenPos(ImVec2(top.x, top.y + h));
    ImGui::Dummy(ImVec2(g_card.w, 0));
    ImGui::SetCursorScreenPos(ImVec2(top.x, top.y + h));
}

float seg_width(const std::vector<std::string>& labels) {
    float w = 4;
    for (auto& l : labels) w += ImGui::CalcTextSize(l.c_str()).x + 22;
    return w;
}

bool seg(const char* id, int* v, const std::vector<std::string>& labels) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float h = ImGui::GetFrameHeight(), w = seg_width(labels);
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), col(P.track), 7.0f);
    bool changed = false;
    float x = p.x + 2;
    ImGui::PushID(id);
    for (int i = 0; i < int(labels.size()); i++) {
        float iw = ImGui::CalcTextSize(labels[size_t(i)].c_str()).x + 22;
        ImGui::SetCursorScreenPos(ImVec2(x, p.y));
        ImGui::PushID(i);
        if (ImGui::InvisibleButton("##s", ImVec2(iw, h)) && *v != i) {
            *v = i;
            changed = true;
        }
        focus_ring(6.0f);
        bool hov = ImGui::IsItemHovered(), held = ImGui::IsItemActive();
        ImGui::PopID();
        ImVec2 a(x, p.y + 2), b(x + iw, p.y + h - 2);
        if (*v == i) {
            if (!P.dark) dl->AddRectFilled(ImVec2(a.x, a.y + 1), ImVec2(b.x, b.y + 1), col(ImVec4(0, 0, 0, 0.08f)), 6.0f);
            dl->AddRectFilled(a, b, col(P.pill), 6.0f);
            dl->AddRect(a, b, col(P.border), 6.0f);
        } else if (held) {  // responds on press, before release
            dl->AddRectFilled(a, b, ImGui::GetColorU32(ImGuiCol_FrameBgActive), 6.0f);
        } else if (hov) {
            dl->AddRectFilled(a, b, col(P.hover), 6.0f);
        }
        ImVec2 ts = ImGui::CalcTextSize(labels[size_t(i)].c_str());
        dl->AddText(ImVec2(x + (iw - ts.x) / 2, p.y + (h - ts.y) / 2), col(*v == i || hov ? P.text : P.dim), labels[size_t(i)].c_str());
        x += iw;
    }
    ImGui::PopID();
    ImGui::SetCursorScreenPos(ImVec2(p.x, p.y + h));
    ImGui::Dummy(ImVec2(w, 0));
    g_dirty |= changed;
    return changed;
}

bool choice(const char* title, const char* desc, int* v, const std::vector<std::string>& labels, const char* more) {
    bool ch = false;
    row(title, desc, seg_width(labels), [&] { ch = seg(title, v, labels); }, more);
    return ch;
}

bool toggle(const char* title, const char* desc, bool* b, const char* more) {
    int v = *b ? 1 : 0;
    bool ch = choice(title, desc, &v, {"Off", "On"}, more);
    *b = v == 1;
    return ch;
}

bool text(const char* title, const char* desc, std::string& value, float w, const char* hint, bool password) {
    bool ch = false;
    row(title, desc, w, [&] {
        char buf[512];
        snprintf(buf, sizeof buf, "%s", value.c_str());
        ImGui::SetNextItemWidth(w);
        if (ImGui::InputTextWithHint("##t", hint, buf, sizeof buf, password ? ImGuiInputTextFlags_Password : 0)) value = buf;
        if (ImGui::IsItemDeactivatedAfterEdit()) ch = true;
    });
    g_dirty |= ch;
    return ch;
}

bool number(const char* title, const char* desc, int* v, int lo, int hi, float w) {
    bool ch = false;
    row(title, desc, w, [&] {
        ImGui::SetNextItemWidth(w);
        ImGui::InputInt("##n", v);
        *v = std::clamp(*v, lo, hi);
        if (ImGui::IsItemDeactivatedAfterEdit()) ch = true;
    });
    g_dirty |= ch;
    return ch;
}

bool action(const char* title, const char* desc, const char* label, Btn kind, bool enabled) {
    bool pressed = false;
    float w = ImGui::CalcTextSize(label).x + 28;
    row(title, desc, w, [&] { pressed = button(label, kind, ImVec2(w, 0), enabled); });
    return pressed;
}

void info(const char* title, const char* desc, const char* value, const ImVec4* value_col) {
    float w = std::min(ImGui::CalcTextSize(value).x + (value_col ? 14 : 0), g_card.w * 0.55f);
    row(title, desc, w, [&] {
        ImGui::AlignTextToFramePadding();
        if (value_col) status_text(*value_col, value);
        else ImGui::TextDisabled("%s", value);
    });
}

}  // namespace prefs

}  // namespace s3v::ui
