// POSIX libc pieces MinGW does not provide: fnmatch (the subset .s3vaultignore uses) and strptime (the
// fixed formats of HTTP dates and trash timestamps).
#ifdef _WIN32
#include "util/compat.h"

#include <cctype>
#include <cstdlib>
#include <cstring>

static bool class_match(const char*& p, char c, int flags) {
    // p points after '['; on success leaves p after ']'.
    bool neg = *p == '!' || *p == '^';
    if (neg) p++;
    bool hit = false;
    const char* start = p;
    while (*p && (*p != ']' || p == start)) {
        char lo = *p++;
        if (*p == '-' && p[1] && p[1] != ']') {
            char hi = p[1];
            p += 2;
            if (c >= lo && c <= hi) hit = true;
        } else if (c == lo) {
            hit = true;
        }
    }
    if (*p == ']') p++;
    if ((flags & FNM_PATHNAME) && c == '/') return false;
    return hit != neg;
}

static bool match(const char* p, const char* s, int flags) {
    for (; *p; p++, s++) {
        switch (*p) {
        case '?':
            if (!*s || ((flags & FNM_PATHNAME) && *s == '/')) return false;
            break;
        case '*': {
            while (p[1] == '*') p++;
            if (!p[1]) return !(flags & FNM_PATHNAME) || !strchr(s, '/');
            for (const char* t = s; *t; t++) {
                if (match(p + 1, t, flags)) return true;
                if ((flags & FNM_PATHNAME) && *t == '/') return false;
            }
            return match(p + 1, s + strlen(s), flags);
        }
        case '[': {
            if (!*s) return false;
            const char* q = p + 1;
            if (!class_match(q, *s, flags)) return false;
            p = q - 1;
            break;
        }
        case '\\':
            if (p[1]) p++;
            [[fallthrough]];
        default:
            if (*p != *s) return false;
        }
    }
    return !*s;
}

int fnmatch(const char* pattern, const char* string, int flags) { return match(pattern, string, flags) ? 0 : FNM_NOMATCH; }

char* strptime(const char* s, const char* f, struct tm* tm) {
    static const char* mon[] = {"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"};
    auto num = [&](int digits, int& out) {
        int v = 0, n = 0;
        while (n < digits && isdigit(static_cast<unsigned char>(*s))) v = v * 10 + (*s++ - '0'), n++;
        out = v;
        return n > 0;
    };
    for (; *f; f++) {
        if (*f != '%') {
            if (isspace(static_cast<unsigned char>(*f))) { while (isspace(static_cast<unsigned char>(*s))) s++; continue; }
            if (*s++ != *f) return nullptr;
            continue;
        }
        int v = 0;
        switch (*++f) {
        case 'Y': if (!num(4, v)) return nullptr; tm->tm_year = v - 1900; break;
        case 'm': if (!num(2, v)) return nullptr; tm->tm_mon = v - 1; break;
        case 'd': if (!num(2, v)) return nullptr; tm->tm_mday = v; break;
        case 'H': if (!num(2, v)) return nullptr; tm->tm_hour = v; break;
        case 'M': if (!num(2, v)) return nullptr; tm->tm_min = v; break;
        case 'S': if (!num(2, v)) return nullptr; tm->tm_sec = v; break;
        case 'a': while (isalpha(static_cast<unsigned char>(*s))) s++; break;
        case 'b': {
            int i = 0;
            for (; i < 12; i++)
                if (!_strnicmp(s, mon[i], 3)) break;
            if (i == 12) return nullptr;
            tm->tm_mon = i;
            while (isalpha(static_cast<unsigned char>(*s))) s++;
            break;
        }
        case '%': if (*s++ != '%') return nullptr; break;
        default: return nullptr;
        }
    }
    return const_cast<char*>(s);
}
#endif
