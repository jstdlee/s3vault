#include "i18n.h"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <string_view>
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#endif

namespace s3v::ui {

namespace {

struct Entry {
    const char* en;
    const char* zh;
    const char* ja;
    const char* ko;
};

#include "i18n_table.inc"

Lang g_lang = Lang::En;

const std::unordered_map<std::string_view, const Entry*>& index() {
    static const auto m = [] {
        std::unordered_map<std::string_view, const Entry*> r;
        for (const Entry& e : kTable) r.emplace(e.en, &e);
        return r;
    }();
    return m;
}

std::unordered_map<std::string, std::string>& cache() {
    static std::unordered_map<std::string, std::string> c;
    return c;
}

Lang from_locale() {
    std::string l;
#ifdef _WIN32
    wchar_t buf[LOCALE_NAME_MAX_LENGTH] = {};
    if (GetUserDefaultLocaleName(buf, LOCALE_NAME_MAX_LENGTH))
        for (wchar_t* p = buf; *p && p - buf < 8; p++) l += char(*p);
#else
    for (const char* v : {"LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"})
        if (const char* s = getenv(v); s && *s) { l = s; break; }
#endif
    if (l.rfind("zh", 0) == 0) return Lang::Zh;
    if (l.rfind("ja", 0) == 0) return Lang::Ja;
    if (l.rfind("ko", 0) == 0) return Lang::Ko;
    return Lang::En;
}

// Bytes of leading icon glyphs (Private Use Area, U+E000–U+F8FF) and the spaces after them.
size_t icon_prefix(std::string_view s) {
    size_t i = 0;
    for (;;) {
        if (i + 2 < s.size() && (unsigned char)s[i] == 0xEE) { i += 3; continue; }
        if (i + 2 < s.size() && (unsigned char)s[i] == 0xEF && (unsigned char)s[i + 1] <= 0xA3) { i += 3; continue; }
        break;
    }
    if (i == 0) return 0;
    while (i < s.size() && s[i] == ' ') i++;
    return i;
}

}  // namespace

void set_language(const std::string& setting) {
    Lang l = setting == "zh" ? Lang::Zh : setting == "ja" ? Lang::Ja : setting == "ko" ? Lang::Ko : setting == "en" ? Lang::En : from_locale();
    if (l != g_lang) cache().clear();
    g_lang = l;
}

Lang language() { return g_lang; }

const char* language_code() { return g_lang == Lang::Zh ? "zh" : g_lang == Lang::Ja ? "ja" : g_lang == Lang::Ko ? "ko" : "en"; }

const char* tr(const char* en) {
    if (!en || g_lang == Lang::En || !*en) return en;
    auto& c = cache();
    if (auto it = c.find(en); it != c.end()) return it->second.c_str();
    std::string_view s(en);
    size_t a = icon_prefix(s);
    size_t b = s.find("##");
    if (b == std::string_view::npos) b = s.size();
    std::string_view mid = b > a ? s.substr(a, b - a) : std::string_view();
    // Keep leading/trailing spaces of the words (e.g. "  Edit" after an icon written as two literals).
    size_t l = 0, r = mid.size();
    while (l < r && mid[l] == ' ') l++;
    while (r > l && mid[r - 1] == ' ') r--;
    std::string out(en);
    auto& idx = index();
    if (auto it = idx.find(mid.substr(l, r - l)); it != idx.end()) {
        const Entry* e = it->second;
        const char* t = g_lang == Lang::Zh ? e->zh : g_lang == Lang::Ja ? e->ja : e->ko;
        if (t && *t) out = std::string(s.substr(0, a + l)) + t + std::string(mid.substr(r)) + std::string(s.substr(b));
    }
    return c.emplace(en, std::move(out)).first->second.c_str();
}

std::string trf(const char* fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, tr(fmt), ap);
    va_end(ap);
    return buf;
}

std::string tr_n(size_t n, const char* one_fmt, const char* many_fmt) {
    // Chinese, Japanese and Korean have no plural: the "many" entry carries the counter word.
    const char* f = g_lang != Lang::En ? tr(many_fmt) : n == 1 ? one_fmt : many_fmt;
    char buf[256];
    snprintf(buf, sizeof buf, f, n);
    return buf;
}

}  // namespace s3v::ui
