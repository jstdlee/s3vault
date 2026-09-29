#include "preview/preview.h"

#include <algorithm>
#include <cstdlib>

#include "platform.h"
#include "util/fs.h"
#include "util/secure.h"
#include "util/sha256.h"
#include "util/strings.h"
#include "util/subprocess.h"

namespace s3v {

PreviewKind preview_kind(const std::string& logical) {
    std::string e = path_ext_lower(logical);
    static const char* text[] = {"txt", "md", "markdown", "rst", "log", "csv", "tsv", "json", "jsonl", "yaml", "yml",
                                 "toml", "ini", "cfg", "conf", "xml", "html", "htm", "css", "js", "ts", "tsx", "jsx",
                                 "c", "h", "cc", "cpp", "hpp", "cxx", "py", "rb", "go", "rs", "java", "kt", "swift",
                                 "sh", "bash", "zsh", "fish", "ps1", "bat", "sql", "lua", "pl", "php", "r", "m",
                                 "tex", "org", "env", "gitignore", "dockerfile", "makefile", "cmake", "srt", "vtt"};
    for (auto* t : text)
        if (e == t) return PreviewKind::Text;
    std::string b = to_lower(path_basename(logical));
    if (b == "readme" || b == "license" || b == "makefile" || b == "dockerfile" || e.empty()) return PreviewKind::Text;
    static const char* img[] = {"png", "jpg", "jpeg", "gif", "bmp", "tga", "psd", "pnm", "ppm", "pgm", "hdr"};
    for (auto* t : img)
        if (e == t) return PreviewKind::Image;
    if (e == "pdf") return PreviewKind::Pdf;
    return PreviewKind::None;
}

const char* file_type_label(const std::string& logical) {
    std::string e = path_ext_lower(logical);
    switch (preview_kind(logical)) {
        case PreviewKind::Image: return "Image";
        case PreviewKind::Pdf: return "PDF";
        case PreviewKind::Text: {
            static const char* code[] = {"c", "h", "cc", "cpp", "hpp", "cxx", "py", "rb", "go", "rs", "java", "kt",
                                         "swift", "js", "ts", "tsx", "jsx", "sh", "bash", "zsh", "lua", "pl",
                                         "php", "sql", "html", "css", "xml", "json", "yaml", "yml", "toml"};
            for (auto* c : code)
                if (e == c) return "Code";
            return "Text";
        }
        case PreviewKind::None: break;
    }
    static const char* audio[] = {"mp3", "m4a", "aac", "ogg", "opus", "flac", "wav"};
    static const char* video[] = {"mp4", "mkv", "mov", "webm", "avi", "m4v"};
    static const char* arch[] = {"zip", "gz", "tgz", "bz2", "xz", "zst", "7z", "rar", "tar"};
    static const char* doc[] = {"doc", "docx", "odt", "rtf", "xls", "xlsx", "ods", "ppt", "pptx", "odp", "epub"};
    static const char* img2[] = {"webp", "heic", "avif", "svg", "tif", "tiff", "ico"};
    for (auto* x : audio) if (e == x) return "Audio";
    for (auto* x : video) if (e == x) return "Video";
    for (auto* x : arch) if (e == x) return "Archive";
    for (auto* x : doc) if (e == x) return "Document";
    for (auto* x : img2) if (e == x) return "Image";
    return "File";
}

bool utf8_valid(std::string_view s) {
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == 0) return false;  // NUL bytes: treat as binary
        int n = c < 0x80 ? 0 : (c >> 5) == 6 ? 1 : (c >> 4) == 14 ? 2 : (c >> 3) == 30 ? 3 : -1;
        if (n < 0 || i + size_t(n) >= s.size() + (n ? 0 : 1)) return n == 0;
        for (int k = 1; k <= n; k++)
            if ((static_cast<unsigned char>(s[i + size_t(k)]) >> 6) != 2) return false;
        i += size_t(n) + 1;
    }
    return true;
}

PreviewLimits PreviewLimits::from(const PreviewConfig& c) {
    PreviewLimits l;
    l.text_max = size_t(std::max(1, c.text_max_mb)) << 20;
    l.image_max = size_t(std::max(1, c.image_max_mb)) << 20;
    l.pdf_max = size_t(std::max(1, c.pdf_max_mb)) << 20;
    l.image_max_pixels = int64_t(std::max(1, c.image_max_mpix)) * 1000000;
    l.pdf_dpi = std::min(150, std::max(40, c.pdf_dpi));
    return l;
}

size_t PreviewLimits::cap_for(PreviewKind k) const {
    switch (k) {
        case PreviewKind::Text: return text_max;
        case PreviewKind::Image: return image_max;
        case PreviewKind::Pdf: return pdf_max;
        default: return text_max;
    }
}

OpResult load_preview_bytes(Vault& v, const RemoteEntry& e, size_t cap, std::string& out) {
    // Encrypted objects are a few dozen bytes bigger than the plaintext; plain ones are exact.
    if (e.size > cap + (e.encrypted ? 4096 : 0)) {
        OpResult r = OpResult::fail("too large to preview (" + human_size(e.size) + ", limit " + human_size(cap) + ")");
        r.too_large = true;
        return r;
    }
    return v.download_to_memory(e.key, out, cap);
}

bool PdfDoc::open(const std::string& bytes, std::string& error) {
    close();
    std::string dir = platform::session_tmp_dir() + "/preview";
    mkdirs(dir, 0700);
    path_ = dir + "/" + to_hex(random_bytes(8)) + ".pdf";
    if (!write_file_atomic(path_, bytes, 0600)) {
        error = "cannot write preview file";
        path_.clear();
        return false;
    }
    std::string out, err;
    int rc = run_capture({"pdfinfo", path_}, "", &out, &err, 1 << 20, 10000);
    if (rc != 0) {
        error = rc == -3 ? "pdfinfo timed out" : "not a readable PDF" + (err.empty() ? "" : ": " + trim(err));
        close();
        return false;
    }
    for (auto& l : split(out, '\n'))
        if (starts_with(l, "Pages:")) pages_ = atoi(trim(l.substr(6)).c_str());
    if (pages_ <= 0) {
        error = "PDF has no pages";
        close();
        return false;
    }
    return true;
}

bool PdfDoc::render(int page, int dpi, std::string& png, std::string& error) {
    if (path_.empty()) { error = "no document"; return false; }
    std::string exe = find_executable("pdftoppm");
    if (exe.empty()) { error = "pdftoppm not found (install poppler-utils)"; return false; }
    std::string err;
    std::string p = std::to_string(page);
    // -scale-to bounds the long side (≈ dpi × 12 in, max 2400 px) whatever page size the file claims.
    int long_side = std::min(2400, dpi * 12);
    int rc = run_capture({exe, "-png", "-singlefile", "-f", p, "-l", p, "-scale-to", std::to_string(long_side), path_},
                         "", &png, &err, 64u << 20, 10000);
    if (rc != 0) {
        error = rc == -3 ? "page took too long to render" : rc == -2 ? "page image too large" : "pdftoppm failed: " + trim(err);
        png.clear();
        return false;
    }
    return true;
}

void PdfDoc::close() {
    if (!path_.empty()) secure_unlink(path_);
    path_.clear();
    pages_ = 0;
}

}  // namespace s3v
