// Child processes with pipes (gpg, pdftoppm). posix_spawn on POSIX, CreateProcess on Windows (subprocess_win.cpp).
#pragma once
#include <sys/types.h>

#include <cstdint>

#include <string>
#include <vector>

namespace s3v {

struct SpawnOpts {
    std::vector<std::string> argv;
    bool pipe_stdin = false;   // parent writes → child stdin
    bool pipe_stdout = false;  // child stdout → parent reads
    bool pipe_stderr = false;  // child stderr → parent reads
    int stdin_fd = -1;         // or redirect stdin from this fd (not closed by spawn)
    int stdout_fd = -1;        // or redirect stdout to this fd
    std::string fd3_data;      // if set: child gets it on fd 3 (a pipe, fully written then closed); on Windows an
                               // inherited pipe handle whose number replaces any argv entry equal to kFd3Arg
    bool has_fd3 = false;
    bool detach = false;       // new session; not waited for (external viewers/editors)
};

// The argv value naming the extra descriptor (e.g. "--passphrase-fd", kFd3Arg): "3" on POSIX.
extern const char* const kFd3Arg;

#ifdef _WIN32
using proc_id = intptr_t;  // process HANDLE
#else
using proc_id = pid_t;
#endif

struct Proc {
    proc_id pid = -1;
    int in = -1, out = -1, err = -1;
};

bool spawn(const SpawnOpts& o, Proc& p, std::string* error = nullptr);
// Waits and returns the exit code; -1 if killed or not started.
int wait_proc(Proc& p);
void kill_proc(Proc& p);
void close_fds(Proc& p);

// Run to completion. Feeds `input` to stdin (if non-empty or pipe_input), captures stdout/stderr.
// Stops reading stdout after `max_out` bytes (child is killed; returns -2). timeout_ms 0 = none (-3 on timeout).
int run_capture(const std::vector<std::string>& argv, const std::string& input, std::string* out, std::string* err,
                size_t max_out = size_t(-1), int timeout_ms = 0, bool pipe_input = false);

// Absolute path of an executable found on PATH (or the given path if it is executable); "" if not found.
std::string find_executable(const std::string& name);

// Read everything from fd until EOF (or max bytes; returns false if exceeded).
bool read_all_fd(int fd, std::string& out, size_t max = size_t(-1));
bool write_all_fd(int fd, const void* data, size_t len);

}  // namespace s3v
