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

static void image_view(Preview& p) {
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float fit = std::min(avail.x / float(p.w), (avail.y - 4) / float(p.h));
    fit = std::min(fit, 1.0f);
    float z = p.zoom > 0 ? p.zoom : fit;
    ImGui::BeginChild("img", ImVec2(0, 0), 0, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::Image(ImTextureRef((ImTextureID)(intptr_t)p.tex), ImVec2(float(p.w) * z, float(p.h) * z));
    if (ImGui::IsWindowHovered() && ImGui::GetIO().KeyCtrl && ImGui::GetIO().MouseWheel != 0) {
        p.zoom = std::clamp(z * (ImGui::GetIO().MouseWheel > 0 ? 1.15f : 1 / 1.15f), 0.05f, 8.0f);
    }
    ImGui::EndChild();
}

void draw_preview(App& a, const Node* sel) {
    Preview& p = a.preview;
    if (p.state == PreviewState::Empty) return;
    if (!sel || sel->logical != p.logical) return;
    ImGui::Text("%s Preview", ICON_FA_EYE);
    ImGui::SameLine();
    if (ImGui::SmallButton(ICON_FA_XMARK " Close preview")) {
        preview_free(a);
        return;
    }
    if (p.kind != PreviewKind::Text && p.state == PreviewState::Ready) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Fit")) p.zoom = 0;
        ImGui::SameLine();
        if (ImGui::SmallButton("100%")) p.zoom = 1;
        ImGui::SameLine();
        ImGui::TextDisabled("%d×%d · Ctrl+wheel to zoom", p.w, p.h);
    }
    if (p.pdf && p.pdf->is_open()) {
        ImGui::SameLine();
        ImGui::BeginDisabled(p.page_loading || p.page <= 1);
        if (ImGui::SmallButton("◀")) render_pdf_page(a, p.page - 1);
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::Text("Page %d / %d", p.page, p.pdf->pages());
        ImGui::SameLine();
        ImGui::BeginDisabled(p.page_loading || p.page >= p.pdf->pages());
        if (ImGui::SmallButton("▶")) render_pdf_page(a, p.page + 1);
        ImGui::EndDisabled();
    }
    switch (p.state) {
        case PreviewState::Loading:
            ImGui::TextDisabled("Loading%s…", sel->entry.encrypted ? " and decrypting" : "");
            return;
        case PreviewState::Error:
            ImGui::TextColored(ImVec4(1, 0.45f, 0.4f, 1), "%s", p.error.c_str());
            if (p.too_large) ImGui::TextDisabled("Use Download to save a copy where you choose.");
            return;
        default: break;
    }
    if (p.kind == PreviewKind::Text) {
        if (p.binary) ImGui::TextDisabled("Not valid UTF-8 text: showing a hex dump of the first 64 KB.");
        ImGui::BeginChild("text", ImVec2(0, 0), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
        ImGuiListClipper clip;
        clip.Begin(int(p.line_starts.size()));
        int digits = int(std::to_string(p.line_starts.size()).size());
        while (clip.Step()) {
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
                size_t s = p.line_starts[size_t(i)];
                size_t e = size_t(i) + 1 < p.line_starts.size() ? p.line_starts[size_t(i) + 1] - 1 : p.text.size();
                if (e > s && p.text[e - 1] == '\n') e--;
                if (!p.binary) {
                    ImGui::TextDisabled("%*d", digits, i + 1);
                    ImGui::SameLine();
                }
                ImGui::TextUnformatted(p.text.data() + s, p.text.data() + e);
            }
        }
        ImGui::EndChild();
    } else if (p.tex) {
        image_view(p);
        if (p.page_loading) ImGui::TextDisabled("Rendering page…");
    }
}

}  // namespace s3v::ui
