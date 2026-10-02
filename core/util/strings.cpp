#include "util/strings.h"

#include <cctype>
#include <cstdio>

#include "util/compat.h"

namespace s3v {

std::string plural(size_t n, const char* one, const char* many) {
    return std::to_string(n) + " " + (n == 1 ? std::string(one) : many ? std::string(many) : std::string(one) + "s");
}

std::string trim(std::string_view s) {
    size_t a = 0, b = s.size();
    while (a < b && isspace(static_cast<unsigned char>(s[a]))) a++;
    while (b > a && isspace(static_cast<unsigned char>(s[b - 1]))) b--;
    return std::string(s.substr(a, b - a));
}

std::vector<std::string> split(std::string_view s, char sep) {
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); i++) {
        if (i == s.size() || s[i] == sep) {
            out.emplace_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}

bool starts_with(std::string_view s, std::string_view p) { return s.size() >= p.size() && s.substr(0, p.size()) == p; }
bool ends_with(std::string_view s, std::string_view p) {
    return s.size() >= p.size() && s.substr(s.size() - p.size()) == p;
}

std::string to_lower(std::string_view s) {
    std::string r(s);
    for (auto& c : r) c = char(tolower(static_cast<unsigned char>(c)));
    return r;
}

std::string uri_encode(std::string_view s, bool encode_slash) {
    static const char* hx = "0123456789ABCDEF";
    std::string r;
    r.reserve(s.size() * 3);
    for (unsigned char c : s) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || (c == '/' && !encode_slash)) {
            r += char(c);
        } else {
            r += '%';
            r += hx[c >> 4];
            r += hx[c & 15];
        }
    }
    return r;
}

int64_t parse_iso8601(std::string_view s) {
    int Y, M, D, h, m, sec;
    std::string t(s);
    if (sscanf(t.c_str(), "%d-%d-%dT%d:%d:%d", &Y, &M, &D, &h, &m, &sec) != 6) return 0;
    struct tm tmv {};
    tmv.tm_year = Y - 1900;
    tmv.tm_mon = M - 1;
    tmv.tm_mday = D;
    tmv.tm_hour = h;
    tmv.tm_min = m;
    tmv.tm_sec = sec;
    return int64_t(timegm(&tmv));
}

std::string format_local_time(int64_t unix_s) {
    if (unix_s <= 0) return "";
    time_t t = time_t(unix_s);
    struct tm tmv {};
    localtime_r(&t, &tmv);
    char b[32];
    strftime(b, sizeof b, "%Y-%m-%d %H:%M", &tmv);
    return b;
}

std::string format_utc_compact(int64_t unix_s) {
    time_t t = time_t(unix_s);
    struct tm tmv {};
    gmtime_r(&t, &tmv);
    char b[32];
    strftime(b, sizeof b, "%Y%m%dT%H%M%SZ", &tmv);
    return b;
}

std::string human_size(uint64_t n) {
    const char* u[] = {"B", "KB", "MB", "GB", "TB"};
    double v = double(n);
    int i = 0;
    while (v >= 1024 && i < 4) { v /= 1024; i++; }
    char b[32];
    if (i == 0) snprintf(b, sizeof b, "%llu B", static_cast<unsigned long long>(n));
    else snprintf(b, sizeof b, "%.1f %s", v, u[i]);
    return b;
}

std::string path_join(std::string_view a, std::string_view b) {
    if (a.empty()) return std::string(b);
    if (b.empty()) return std::string(a);
    std::string r(a);
    if (r.back() != '/') r += '/';
    r += b.front() == '/' ? b.substr(1) : b;
    return r;
}

std::string path_dirname(std::string_view p) {
    while (!p.empty() && p.back() == '/') p.remove_suffix(1);
    size_t i = p.rfind('/');
    return i == std::string_view::npos ? std::string() : std::string(p.substr(0, i));
}

std::string path_basename(std::string_view p) {
    while (!p.empty() && p.back() == '/') p.remove_suffix(1);
    size_t i = p.rfind('/');
    return std::string(i == std::string_view::npos ? p : p.substr(i + 1));
}

std::string path_ext_lower(std::string_view p) {
    std::string b = path_basename(p);
    size_t i = b.rfind('.');
    if (i == std::string::npos || i == 0) return "";
    return to_lower(b.substr(i + 1));
}

}  // namespace s3v
