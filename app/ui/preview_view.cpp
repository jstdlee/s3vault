// On-demand preview: text, images and PDF pages. One preview at a time; freed (wiped) when another is
// opened, the selection changes, the vault locks, or after the idle timeout.
#include "backends/imgui_impl_opengl3_loader.h"
#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>

#include <algorithm>
#include <cstring>

#include "IconsFontAwesome6.h"
#include "app.h"
#include "imgui.h"
#include "util/secure.h"
#include "util/strings.h"

#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_ONLY_JPEG
#define STBI_ONLY_BMP
#define STBI_ONLY_GIF
#define STBI_ONLY_TGA
#define STBI_ONLY_PSD
#define STBI_ONLY_PNM
#define STBI_ONLY_HDR
#define STBI_MAX_DIMENSIONS 16384
#define STBI_NO_STDIO
#include "stb_image.h"

namespace s3v::ui {

static void delete_texture(Preview& p) {
    if (p.tex) {
        GLuint t = p.tex;
        glDeleteTextures(1, &t);
    }
    p.tex = 0;
    p.w = p.h = 0;
}

void preview_free(App& a) {
    Preview& p = a.preview;
    p.generation++;
    wipe(p.text);
    p.line_starts.clear();
    p.line_starts.shrink_to_fit();
    delete_texture(p);
    p.pdf.reset();  // PdfDoc wipes its in-memory copy once no render job holds it
    p.state = PreviewState::Empty;
    p.kind = PreviewKind::None;
    p.error.clear();
    p.too_large = false;
    p.binary = false;
    p.page = 1;
    p.page_loading = false;
    p.zoom = 0;
}

// Decodes image bytes into a texture after checking the dimensions (decompression-bomb guard).
static bool upload_image(App& a, const std::string& bytes, std::string& err) {
    Preview& p = a.preview;
    int w = 0, h = 0, comp = 0;
    if (!stbi_info_from_memory(reinterpret_cast<const stbi_uc*>(bytes.data()), int(bytes.size()), &w, &h, &comp)) {
        err = "unsupported or damaged image";
        return false;
    }
    int64_t max_px = int64_t(std::max(1, a.cfg.preview.image_max_mpix)) * 1000000;
    if (int64_t(w) * h > max_px) {
        err = "image too large to preview (" + std::to_string(w) + "×" + std::to_string(h) + ")";
        return false;
    }
    unsigned char* px = stbi_load_from_memory(reinterpret_cast<const stbi_uc*>(bytes.data()), int(bytes.size()), &w, &h, &comp, 4);
    if (!px) {
        err = stbi_failure_reason() ? stbi_failure_reason() : "decode failed";
        return false;
    }
    GLint max_tex = 4096;
    glGetIntegerv(GL_MAX_TEXTURE_SIZE, &max_tex);
    if (w > max_tex || h > max_tex) {
        explicit_bzero(px, size_t(w) * size_t(h) * 4);
        stbi_image_free(px);
        err = "image larger than the GPU texture limit";
        return false;
    }
    delete_texture(p);
    GLuint tex = 0;
    glGenTextures(1, &tex);
    glBindTexture(GL_TEXTURE_2D, tex);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, px);
    explicit_bzero(px, size_t(w) * size_t(h) * 4);
    stbi_image_free(px);
    p.tex = tex;
    p.w = w;
    p.h = h;
    return true;
}

static void render_pdf_page(App& a, int page) {
    Preview& p = a.preview;
    if (!p.pdf || p.page_loading) return;
    p.page_loading = true;
    uint64_t gen = p.generation;
    std::shared_ptr<PdfDoc> doc = p.pdf;  // keeps the document alive even if the preview is closed meanwhile
    int dpi = std::min(150, std::max(40, a.cfg.preview.pdf_dpi));
    a.run_job([&a, doc, page, dpi, gen] {
        std::string png, err;
        bool ok = doc->render(page, dpi, png, err);
        a.post([&a, gen, page, ok, png = std::move(png), err]() mutable {
            Preview& p = a.preview;
            if (p.generation != gen) { wipe(png); return; }  // preview closed meanwhile
            p.page_loading = false;
            std::string e = err;
            if (ok && upload_image(a, png, e)) {
                p.page = page;
                p.state = PreviewState::Ready;
            } else {
                p.error = e;
                p.state = PreviewState::Error;
            }
            wipe(png);
        });
    });
}

void preview_load(App& a, const RemoteEntry& e) {
    preview_free(a);
    Preview& p = a.preview;
    p.kind = preview_kind(e.logical);
    p.logical = e.logical;
    p.key = e.key;
    p.state = PreviewState::Loading;
    p.last_used = glfwGetTime();
    if (p.kind == PreviewKind::None) {
        p.state = PreviewState::Error;
        p.error = "no preview for this type";
        return;
    }
    if (e.encrypted && !a.vault->unlocked()) {
        preview_free(a);
        a.modal = "unlock";
        return;
    }
    PreviewLimits lim = PreviewLimits::from(a.cfg.preview);
    size_t cap = lim.cap_for(p.kind);
    uint64_t gen = p.generation;
    auto v = a.vault;
    PreviewKind kind = p.kind;
    a.run_job([&a, v, e, cap, gen, kind] {
        std::string bytes;
        OpResult r = load_preview_bytes(*v, e, cap, bytes);
        std::unique_ptr<PdfDoc> doc;
        std::string err = r.error;
        if (r.ok && kind == PreviewKind::Pdf) {
            doc = std::make_unique<PdfDoc>();
            if (!doc->open(std::move(bytes), err)) doc.reset();
            wipe(bytes);
        }
        a.post([&a, gen, kind, r, err, bytes = std::move(bytes), doc = std::shared_ptr<PdfDoc>(doc.release())]() mutable {
            Preview& p = a.preview;
            if (p.generation != gen) {  // user moved on: drop the plaintext immediately
                wipe(bytes);
                if (doc) doc->close();
                return;
            }
            if (!r.ok || (kind == PreviewKind::Pdf && !doc)) {
                p.state = PreviewState::Error;
                p.error = err;
                p.too_large = r.too_large;
                wipe(bytes);
                return;
            }
            if (kind == PreviewKind::Text) {
                p.binary = !utf8_valid(bytes);
                if (p.binary) {
                    // Hex dump of the first 64 KB.
                    std::string hex;
                    size_t n = std::min<size_t>(bytes.size(), 65536);
                    char line[100];
                    for (size_t off = 0; off < n; off += 16) {
                        int k = snprintf(line, sizeof line, "%08zx  ", off);
                        for (size_t i = 0; i < 16; i++)
                            k += snprintf(line + k, sizeof line - size_t(k), i + off < n ? "%02x " : "   ",
                                          i + off < n ? static_cast<unsigned char>(bytes[off + i]) : 0);
                        k += snprintf(line + k, sizeof line - size_t(k), " ");
                        for (size_t i = 0; i < 16 && i + off < n; i++) {
                            unsigned char ch = static_cast<unsigned char>(bytes[off + i]);
                            line[k++] = ch >= 32 && ch < 127 ? char(ch) : '.';
                        }
                        line[k++] = '\n';
                        hex.append(line, size_t(k));
                    }
                    wipe(bytes);
                    p.text = std::move(hex);
                } else {
                    p.text = std::move(bytes);
                }
                p.line_starts.clear();
                p.line_starts.push_back(0);
                for (size_t i = 0; i < p.text.size(); i++)
                    if (p.text[i] == '\n' && i + 1 < p.text.size()) p.line_starts.push_back(uint32_t(i + 1));
                p.state = PreviewState::Ready;
            } else if (kind == PreviewKind::Image) {
                std::string e2;
                if (upload_image(a, bytes, e2)) p.state = PreviewState::Ready;
                else { p.state = PreviewState::Error; p.error = e2; }
                wipe(bytes);
            } else {
                p.pdf = doc;
                render_pdf_page(a, 1);
            }
        });
    });
}

void preview_tick(App& a) {
    Preview& p = a.preview;
    if (p.state == PreviewState::Empty) return;
    double idle = glfwGetTime() - std::max(p.last_used, a.last_input);
    if (idle > std::max(10, a.cfg.preview.idle_free_seconds)) {
        preview_free(a);
        a.notify("Preview closed after inactivity");
    }
}

static void image_view(Preview& p, float height) {
    float avail_w = ImGui::GetContentRegionAvail().x;
    float fit = std::min(avail_w / float(p.w), (height - 4) / float(p.h));
    fit = std::min(fit, 1.0f);
    float z = p.zoom > 0 ? p.zoom : fit;
    ImGui::PushStyleColor(ImGuiCol_ChildBg, P.track);
    ImGui::BeginChild("img", ImVec2(avail_w, height), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    ImVec2 sz(float(p.w) * z, float(p.h) * z);
    ImVec2 c = ImGui::GetContentRegionAvail();
    ImGui::SetCursorPos(ImVec2(std::max(0.0f, (c.x - sz.x) / 2), std::max(0.0f, (c.y - sz.y) / 2)));
    ImGui::Image(ImTextureRef((ImTextureID)(intptr_t)p.tex), sz);
    if (ImGui::IsWindowHovered() && ImGui::GetIO().KeyCtrl && ImGui::GetIO().MouseWheel != 0)
        p.zoom = std::clamp(z * (ImGui::GetIO().MouseWheel > 0 ? 1.15f : 1 / 1.15f), 0.05f, 8.0f);
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

// Quick Look area inside the inspector: the content, then a slim control row (close, zoom, pages).
void draw_preview(App& a, const Node* sel, float height) {
    Preview& p = a.preview;
    if (p.state == PreviewState::Empty) return;
    if (!sel || sel->logical != p.logical) return;
    float w = ImGui::GetContentRegionAvail().x;
    float body_h = height - ImGui::GetFrameHeight() - 8;
    switch (p.state) {
        case PreviewState::Loading: {
            ImGui::PushStyleColor(ImGuiCol_ChildBg, P.track);
            ImGui::BeginChild("##loading", ImVec2(w, body_h));
            ImGui::SetCursorPos(ImVec2(w / 2 - 50, body_h / 2 - 10));
            spinner(8, P.dim);
            ImGui::SameLine();
            ImGui::TextDisabled(sel->entry.encrypted ? "Decrypting…" : "Loading…");
            ImGui::EndChild();
            ImGui::PopStyleColor();
            break;
        }
        case PreviewState::Error: {
            ImGui::PushStyleColor(ImGuiCol_ChildBg, P.track);
            ImGui::BeginChild("##err", ImVec2(w, body_h));
            ImGui::SetCursorPos(ImVec2(12, 12));
            ImGui::PushTextWrapPos(w - 12);
            ImGui::TextColored(P.red, ICON_FA_CIRCLE_EXCLAMATION "  %s", p.error.c_str());
            if (p.too_large) ImGui::TextDisabled("Use Download to save a copy where you choose.");
            ImGui::PopTextWrapPos();
            ImGui::EndChild();
            ImGui::PopStyleColor();
            break;
        }
        default:
            if (p.kind == PreviewKind::Text) {
                ImGui::PushStyleColor(ImGuiCol_ChildBg, P.track);
                ImGui::BeginChild("##text", ImVec2(w, body_h), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
                if (g_mono) ImGui::PushFont(g_mono, ImGui::GetStyle().FontSizeBase * 0.9f);
                ImGuiListClipper clip;
                clip.Begin(int(p.line_starts.size()));
                int digits = int(std::to_string(p.line_starts.size()).size());
                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 6);
                while (clip.Step()) {
                    for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
                        size_t s0 = p.line_starts[size_t(i)];
                        size_t e = size_t(i) + 1 < p.line_starts.size() ? p.line_starts[size_t(i) + 1] - 1 : p.text.size();
                        if (e > s0 && p.text[e - 1] == '\n') e--;
                        ImGui::SetCursorPosX(8);
                        if (!p.binary) {
                            ImGui::TextColored(P.faint, "%*d", digits, i + 1);
                            ImGui::SameLine(0, 10);
                        }
                        ImGui::TextUnformatted(p.text.data() + s0, p.text.data() + e);
                    }
                }
                if (g_mono) ImGui::PopFont();
                ImGui::EndChild();
                ImGui::PopStyleColor();
            } else if (p.tex) {
                image_view(p, body_h);
            }
    }
    // Controls
    ImGui::Dummy(ImVec2(0, 2));
    if (icon_button(ICON_FA_XMARK, "Close preview  (Space)", false, true, 26)) {
        preview_free(a);
        return;
    }
    if (p.kind != PreviewKind::Text && p.state == PreviewState::Ready) {
        ImGui::SameLine(0, 2);
        if (icon_button(ICON_FA_EXPAND, "Fit", p.zoom == 0, true, 26)) p.zoom = 0;
        ImGui::SameLine(0, 2);
        if (icon_button(ICON_FA_MAGNIFYING_GLASS_PLUS, "Actual size (Ctrl+wheel zooms)", p.zoom == 1, true, 26)) p.zoom = 1;
    }
    if (p.pdf && p.pdf->is_open()) {
        ImGui::SameLine(0, 10);
        if (icon_button(ICON_FA_CHEVRON_LEFT, "Previous page", false, !p.page_loading && p.page > 1, 26)) render_pdf_page(a, p.page - 1);
        ImGui::SameLine(0, 2);
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
        small_dim("%d / %d", p.page, p.pdf->pages());
        ImGui::SameLine(0, 2);
        if (icon_button(ICON_FA_CHEVRON_RIGHT, "Next page", false, !p.page_loading && p.page < p.pdf->pages(), 26)) render_pdf_page(a, p.page + 1);
    } else if (p.kind == PreviewKind::Text && p.state == PreviewState::Ready) {
        ImGui::SameLine(0, 8);
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
        small_dim(p.binary ? "Not text — hex dump of the first 64 KB" : "%zu lines", p.line_starts.size());
    } else if (p.tex) {
        ImGui::SameLine(0, 8);
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4);
        small_dim("%d × %d", p.w, p.h);
    }
}

}  // namespace s3v::ui
