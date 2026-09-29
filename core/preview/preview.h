// On-demand, size-bounded preview loading. Nothing here runs unless the user asks for a preview.
#pragma once
#include <cstdint>
#include <string>
#include <string_view>

#include "config/config.h"
#include "vault/vault.h"

namespace s3v {

enum class PreviewKind { None, Text, Image, Pdf };

PreviewKind preview_kind(const std::string& logical);
const char* file_type_label(const std::string& logical);  // "Text", "Image", "PDF", "Archive", …
bool utf8_valid(std::string_view s);

struct PreviewLimits {
    size_t text_max, image_max, pdf_max;
    int64_t image_max_pixels;
    int pdf_dpi;
    static PreviewLimits from(const PreviewConfig& c);
    size_t cap_for(PreviewKind k) const;
};

// Downloads (and decrypts) at most `cap` bytes into `out`. The caller owns and wipes `out`.
OpResult load_preview_bytes(Vault& v, const RemoteEntry& e, size_t cap, std::string& out);

// A PDF held in the session tmp dir only while the preview is open.
class PdfDoc {
public:
    ~PdfDoc() { close(); }
    bool open(const std::string& bytes, std::string& error);  // writes 0600 file, reads page count
    int pages() const { return pages_; }
    // PNG bytes of one page (1-based). Bounded by timeout and output size.
    bool render(int page, int dpi, std::string& png, std::string& error);
    void close();
    bool is_open() const { return !path_.empty(); }

private:
    std::string path_;
    int pages_ = 0;
};

}  // namespace s3v
