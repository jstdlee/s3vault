#include "util/subprocess.h"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <thread>

#include "util/strings.h"

extern char** environ;

namespace s3v {

bool write_all_fd(int fd, const void* data, size_t len) {
    const char* p = static_cast<const char*>(data);
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += n;
        len -= size_t(n);
    }
    return true;
}

bool read_all_fd(int fd, std::string& out, size_t max) {
    char buf[65536];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return true;
        if (out.size() + size_t(n) > max) {
            out.append(buf, max - out.size());
            return false;
        }
        out.append(buf, size_t(n));
    }
}

// Returns a CLOEXEC duplicate of fd that is >= 10, so dup2 onto 0..3 always clears CLOEXEC.
static int high_fd(int fd) {
    int h = fcntl(fd, F_DUPFD_CLOEXEC, 10);
    close(fd);
    return h;
}

bool spawn(const SpawnOpts& o, Proc& p, std::string* error) {
    int in_p[2] = {-1, -1}, out_p[2] = {-1, -1}, err_p[2] = {-1, -1}, fd3_p[2] = {-1, -1};
    auto fail = [&](const char* what) {
        if (error) *error = std::string(what) + ": " + strerror(errno);
        for (int f : {in_p[0], in_p[1], out_p[0], out_p[1], err_p[0], err_p[1], fd3_p[0], fd3_p[1]})
            if (f >= 0) close(f);
        return false;
    };
    if (o.argv.empty()) return fail("empty argv");
    auto mk = [&](int* fds) {
        if (pipe2(fds, O_CLOEXEC) != 0) return false;
        fds[0] = high_fd(fds[0]);
        fds[1] = high_fd(fds[1]);
        return fds[0] >= 0 && fds[1] >= 0;
    };
    if (o.pipe_stdin && !mk(in_p)) return fail("pipe");
    if (o.pipe_stdout && !mk(out_p)) return fail("pipe");
    if (o.pipe_stderr && !mk(err_p)) return fail("pipe");
    if (o.has_fd3) {
        if (!mk(fd3_p)) return fail("pipe");
        if (o.fd3_data.size() > 60000) return fail("fd3 data too large");
        if (!write_all_fd(fd3_p[1], o.fd3_data.data(), o.fd3_data.size())) return fail("write fd3");
        close(fd3_p[1]);
        fd3_p[1] = -1;
    }

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    int devnull = -1;
    if (o.pipe_stdin) posix_spawn_file_actions_adddup2(&fa, in_p[0], 0);
    else if (o.stdin_fd >= 0) posix_spawn_file_actions_adddup2(&fa, o.stdin_fd, 0);
    else posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    if (o.pipe_stdout) posix_spawn_file_actions_adddup2(&fa, out_p[1], 1);
    else if (o.stdout_fd >= 0) posix_spawn_file_actions_adddup2(&fa, o.stdout_fd, 1);
    else if (o.detach) posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    if (o.pipe_stderr) posix_spawn_file_actions_adddup2(&fa, err_p[1], 2);
    else if (o.detach) posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    if (o.has_fd3) posix_spawn_file_actions_adddup2(&fa, fd3_p[0], 3);
    (void)devnull;

    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    short flags = POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK;
    if (o.detach) flags |= POSIX_SPAWN_SETSID;
    posix_spawnattr_setflags(&at, flags);
    sigset_t def, mask;
    sigemptyset(&def);
    sigaddset(&def, SIGPIPE);
    sigaddset(&def, SIGINT);
    sigaddset(&def, SIGTERM);
    sigaddset(&def, SIGCHLD);
    posix_spawnattr_setsigdefault(&at, &def);
    sigemptyset(&mask);
    posix_spawnattr_setsigmask(&at, &mask);

    std::vector<char*> av;
    for (auto& s : o.argv) av.push_back(const_cast<char*>(s.c_str()));
    av.push_back(nullptr);
    pid_t pid = -1;
    int rc = posix_spawnp(&pid, av[0], &fa, &at, av.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&at);
    if (in_p[0] >= 0) close(in_p[0]);
    if (out_p[1] >= 0) close(out_p[1]);
    if (err_p[1] >= 0) close(err_p[1]);
    if (fd3_p[0] >= 0) close(fd3_p[0]);
    if (rc != 0) {
        errno = rc;
        in_p[0] = out_p[1] = err_p[1] = fd3_p[0] = -1;
        return fail(("spawn " + o.argv[0]).c_str());
    }
    p.pid = pid;
    p.in = in_p[1];
    p.out = out_p[0];
    p.err = err_p[0];
    if (o.detach) {
        // Reap in the background so no zombie is left; the caller never waits on it.
        std::thread([pid] {
            int st;
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
        }).detach();
        p.pid = -1;
    }
    return true;
}

void close_fds(Proc& p) {
    for (int* f : {&p.in, &p.out, &p.err})
        if (*f >= 0) { close(*f); *f = -1; }
}

int wait_proc(Proc& p) {
    close_fds(p);
    if (p.pid <= 0) return -1;
    int st = 0;
    while (waitpid(p.pid, &st, 0) < 0 && errno == EINTR) {}
    p.pid = -1;
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    return -1;
}

void kill_proc(Proc& p) {
    if (p.pid > 0) kill(p.pid, SIGKILL);
}

int run_capture(const std::vector<std::string>& argv, const std::string& input, std::string* out, std::string* err,
                size_t max_out, int timeout_ms, bool pipe_input) {
    SpawnOpts o;
    o.argv = argv;
    o.pipe_stdin = pipe_input || !input.empty();
    o.pipe_stdout = true;
    o.pipe_stderr = true;
    Proc p;
    if (!spawn(o, p, err)) return -1;
    size_t in_off = 0;
    if (p.in >= 0 && input.empty()) { close(p.in); p.in = -1; }
    if (p.in >= 0) fcntl(p.in, F_SETFL, O_NONBLOCK);
    std::string o_buf, e_buf;
    auto t0 = std::chrono::steady_clock::now();
    int result = 0;
    while (p.out >= 0 || p.err >= 0) {
        pollfd fds[3];
        int n = 0;
        int io = -1, ie = -1, ii = -1;
        if (p.out >= 0) { io = n; fds[n++] = {p.out, POLLIN, 0}; }
        if (p.err >= 0) { ie = n; fds[n++] = {p.err, POLLIN, 0}; }
        if (p.in >= 0) { ii = n; fds[n++] = {p.in, POLLOUT, 0}; }
        int wait_ms = 200;
        int pr = poll(fds, nfds_t(n), wait_ms);
        if (pr < 0 && errno != EINTR) break;
        if (timeout_ms > 0) {
            auto el = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
            if (el.count() > timeout_ms) { result = -3; break; }
        }
        if (pr <= 0) continue;
        char buf[65536];
        if (ii >= 0 && (fds[ii].revents & (POLLOUT | POLLERR | POLLHUP))) {
            ssize_t w = write(p.in, input.data() + in_off, input.size() - in_off);
            if (w > 0) in_off += size_t(w);
            if (w < 0 && errno != EAGAIN && errno != EINTR) in_off = input.size();
            if (in_off >= input.size()) { close(p.in); p.in = -1; }
        }
        if (io >= 0 && (fds[io].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t r = read(p.out, buf, sizeof buf);
            if (r > 0) {
                if (o_buf.size() + size_t(r) > max_out) { result = -2; break; }
                o_buf.append(buf, size_t(r));
            } else if (r == 0 || (errno != EINTR && errno != EAGAIN)) {
                close(p.out); p.out = -1;
            }
        }
        if (ie >= 0 && (fds[ie].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t r = read(p.err, buf, sizeof buf);
            if (r > 0) { if (e_buf.size() < 65536) e_buf.append(buf, size_t(r)); }
            else if (r == 0 || (errno != EINTR && errno != EAGAIN)) { close(p.err); p.err = -1; }
        }
    }
    if (result != 0) kill_proc(p);
    int rc = wait_proc(p);
    if (out) *out = std::move(o_buf);
    if (err) *err = std::move(e_buf);
    return result != 0 ? result : rc;
}

std::string find_executable(const std::string& name) {
    if (name.empty()) return "";
    if (name.find('/') != std::string::npos) return access(name.c_str(), X_OK) == 0 ? name : "";
    const char* path = getenv("PATH");
    for (auto& dir : split(path ? path : "/usr/local/bin:/usr/bin:/bin", ':')) {
        if (dir.empty()) continue;
        std::string f = dir + "/" + name;
        struct stat st{};
        if (stat(f.c_str(), &st) == 0 && S_ISREG(st.st_mode) && access(f.c_str(), X_OK) == 0) return f;
    }
    return "";
}

}  // namespace s3v
