// Small POSIX shims so the portable core compiles with MinGW-w64 on Windows. On POSIX this only includes the
// usual headers. Kept free of <windows.h> (its macros clash with ordinary names); Win32 calls live in .cpp files.
#pragma once
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdlib>

#ifdef _WIN32
#include <direct.h>
#include <io.h>

#include <climits>
#include <cstdlib>

// Windows CRT descriptors default to text mode (CRLF translation) and are inherited by child processes.
#ifndef O_CLOEXEC
#define O_CLOEXEC (_O_BINARY | _O_NOINHERIT)
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef S_ISLNK
#define S_ISLNK(m) 0
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include <ctime>

// libc functions MinGW lacks (compat_win.cpp).
#define FNM_PATHNAME 1
#define FNM_NOMATCH 1
int fnmatch(const char* pattern, const char* string, int flags);
char* strptime(const char* s, const char* format, struct tm* tm);
inline time_t timegm(struct tm* tm) { return _mkgmtime(tm); }
inline struct tm* localtime_r(const time_t* t, struct tm* out) { return localtime_s(out, t) == 0 ? out : nullptr; }
inline struct tm* gmtime_r(const time_t* t, struct tm* out) { return gmtime_s(out, t) == 0 ? out : nullptr; }
#else
#include <fnmatch.h>

#include <ctime>
#endif

namespace s3v {

inline int sync_fd(int fd) {
#ifdef _WIN32
    return _commit(fd);
#else
    return fsync(fd);
#endif
}

inline int set_env(const char* name, const char* value) {
#ifdef _WIN32
    return _putenv_s(name, value);
#else
    return setenv(name, value, 1);
#endif
}

inline int process_id() {
#ifdef _WIN32
    return _getpid();
#else
    return int(getpid());
#endif
}

}  // namespace s3v
