// UI translations: English (source), 简体中文, 日本語, 한국어.
// tr() looks the English text up by content, so it can wrap literals and runtime strings alike. A leading icon
// glyph (and the spaces after it) and a trailing ImGui "##id" are kept and only the words between are translated.
// The widget helpers in theme.cpp call tr() themselves, so most call sites pass plain English.
#pragma once
#include <cstddef>
#include <string>

namespace s3v::ui {

enum class Lang { En, Zh, Ja, Ko };

// "system" (from the desktop's locale), "en", "zh", "ja" or "ko".
void set_language(const std::string& setting);
Lang language();
const char* language_code();  // "en", "zh", "ja", "ko"

// Translated text; the pointer stays valid until the language changes. Unknown text comes back unchanged.
const char* tr(const char* en);
inline const char* tr(const std::string& en) { return tr(en.c_str()); }
// printf with a translated format (translations keep the same conversions, in the same order).
std::string trf(const char* fmt, ...);
// "6 files" / "6 个文件" / "ファイル 6 件" / "파일 6개": `many_fmt` is the English plural with %zu, e.g. "%zu files".
std::string tr_n(size_t n, const char* one_fmt, const char* many_fmt);

}  // namespace s3v::ui
