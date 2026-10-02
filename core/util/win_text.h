// UTF-8 <-> UTF-16 for Win32 calls (Windows builds only).
#pragma once
#ifdef _WIN32
#include <windows.h>

#include <string>

namespace s3v {

inline std::wstring to_wide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring w(size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), w.data(), n);
    return w;
}

inline std::string from_wide(const wchar_t* w, int len = -1) {
    if (!w || !len || (len < 0 && !*w)) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, len, nullptr, 0, nullptr, nullptr);
    std::string s(size_t(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, len, s.data(), n, nullptr, nullptr);
    if (len < 0 && !s.empty() && s.back() == '\0') s.pop_back();
    return s;
}
inline std::string from_wide(const std::wstring& w) { return from_wide(w.c_str(), int(w.size())); }

// "C:\Users\me" -> "C:/Users/me": the code base uses '/' everywhere, which Win32 accepts too.
inline std::string slashes(std::string p) {
    for (auto& c : p)
        if (c == '\\') c = '/';
    return p;
}

}  // namespace s3v
#endif
