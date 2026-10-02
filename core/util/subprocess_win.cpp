// Windows child processes: CreateProcessW with anonymous pipes exposed to the rest of the code as CRT descriptors.
// Only the handles named in PROC_THREAD_ATTRIBUTE_HANDLE_LIST are inherited, so pipes created concurrently on other
// threads never leak into an unrelated child (which would keep them open and hang readers waiting for EOF).
#ifdef _WIN32
#include <windows.h>

#include <fcntl.h>
#include <io.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

#include "util/strings.h"
#include "util/subprocess.h"
#include "util/win_text.h"

namespace s3v {

const char* const kFd3Arg = "\x01" "fd3";

static constexpr UINT kKilled = 0x7e57;  // exit code used by kill_proc; wait_proc reports it as -1

// Quoting rules of CommandLineToArgvW / the MSVC CRT.
static std::wstring quote_arg(const std::wstring& a) {
    if (!a.empty() && a.find_first_of(L" \t\n\v\"") == std::wstring::npos) return a;
    std::wstring r = L"\"";
    for (size_t i = 0;; i++) {
        size_t bs = 0;
        while (i < a.size() && a[i] == L'\\') { i++; bs++; }
        if (i == a.size()) { r.append(bs * 2, L'\\'); break; }
        if (a[i] == L'"') { r.append(bs * 2 + 1, L'\\'); r += L'"'; }
        else { r.append(bs, L'\\'); r += a[i]; }
    }
    return r + L"\"";
}

static std::string last_error(const std::string& what) {
    DWORD e = GetLastError();
    wchar_t* msg = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, e,
                   0, reinterpret_cast<wchar_t*>(&msg), 0, nullptr);
    std::string m = msg ? trim(from_wide(msg)) : "error " + std::to_string(e);
    if (msg) LocalFree(msg);
    return what + ": " + m;
}

// An inheritable duplicate of h (the original is left alone).
static HANDLE inheritable(HANDLE h) {
    HANDLE d = nullptr;
    if (!h || h == INVALID_HANDLE_VALUE) return nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), h, GetCurrentProcess(), &d, 0, TRUE, DUPLICATE_SAME_ACCESS)) return nullptr;
    return d;
}

static HANDLE open_nul(bool write) {
    SECURITY_ATTRIBUTES sa{sizeof sa, nullptr, TRUE};
    return CreateFileW(L"NUL", write ? GENERIC_WRITE : GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                       OPEN_EXISTING, 0, nullptr);
}

// Pipe whose `child_reads` end (read end if true) is inheritable; the other end is not.
static bool make_pipe(HANDLE& parent_end, HANDLE& child_end, bool child_reads, DWORD size = 0) {
    HANDLE r = nullptr, w = nullptr;
    if (!CreatePipe(&r, &w, nullptr, size)) return false;
    child_end = child_reads ? r : w;
    parent_end = child_reads ? w : r;
    SetHandleInformation(child_end, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    return true;
}

bool spawn(const SpawnOpts& o, Proc& p, std::string* error) {
    if (o.argv.empty()) {
        if (error) *error = "empty argv";
        return false;
    }
    std::string exe = find_executable(o.argv[0]);
    if (exe.empty()) {
        if (error) *error = "spawn " + o.argv[0] + ": not found";
        return false;
    }

    HANDLE child[4] = {nullptr, nullptr, nullptr, nullptr};  // stdin, stdout, stderr, fd3
    HANDLE parent_in = nullptr, parent_out = nullptr, parent_err = nullptr;
    auto cleanup = [&] {
        for (HANDLE h : child)
            if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    };
    auto fail = [&](const std::string& what) {
        if (error) *error = last_error(what);
        cleanup();
        for (HANDLE h : {parent_in, parent_out, parent_err})
            if (h) CloseHandle(h);
        return false;
    };

    if (o.pipe_stdin) { if (!make_pipe(parent_in, child[0], true)) return fail("pipe"); }
    else if (o.stdin_fd >= 0) child[0] = inheritable(HANDLE(_get_osfhandle(o.stdin_fd)));
    else child[0] = open_nul(false);
    if (o.pipe_stdout) { if (!make_pipe(parent_out, child[1], false)) return fail("pipe"); }
    else if (o.stdout_fd >= 0) child[1] = inheritable(HANDLE(_get_osfhandle(o.stdout_fd)));
    else child[1] = o.detach ? open_nul(true) : inheritable(GetStdHandle(STD_OUTPUT_HANDLE));
    if (o.pipe_stderr) { if (!make_pipe(parent_err, child[2], false)) return fail("pipe"); }
    else child[2] = o.detach ? nullptr : inheritable(GetStdHandle(STD_ERROR_HANDLE));
    // A GUI process has no console: give the child NUL rather than an invalid handle.
    if (!child[1] || child[1] == INVALID_HANDLE_VALUE) child[1] = open_nul(true);
    if (!child[2] || child[2] == INVALID_HANDLE_VALUE) child[2] = open_nul(true);
    if (!child[0] || child[0] == INVALID_HANDLE_VALUE) return fail("stdin");

    std::vector<std::string> argv = o.argv;
    if (o.has_fd3) {
        if (o.fd3_data.size() > 60000) { SetLastError(ERROR_BUFFER_OVERFLOW); return fail("fd3 data too large"); }
        HANDLE w = nullptr;
        if (!make_pipe(w, child[3], true, 65536)) return fail("pipe");
        DWORD done = 0;
        bool ok = o.fd3_data.empty() || WriteFile(w, o.fd3_data.data(), DWORD(o.fd3_data.size()), &done, nullptr);
        CloseHandle(w);
        if (!ok || done != o.fd3_data.size()) return fail("write fd3");
        for (auto& a : argv)
            if (a == kFd3Arg) a = std::to_string(uintptr_t(child[3]));
    }

    std::wstring cmd = quote_arg(to_wide(exe));
    for (size_t i = 1; i < argv.size(); i++) cmd += L" " + quote_arg(to_wide(argv[i]));

    HANDLE list[4];
    DWORD nlist = 0;
    for (HANDLE h : child)
        if (h) list[nlist++] = h;
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
    std::vector<char> attr_buf(attr_size);
    auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
    if (!InitializeProcThreadAttributeList(attrs, 1, 0, &attr_size)) return fail("spawn " + o.argv[0]);
    UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, list, nlist * sizeof(HANDLE), nullptr, nullptr);

    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof si;
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = child[0];
    si.StartupInfo.hStdOutput = child[1];
    si.StartupInfo.hStdError = child[2];
    si.lpAttributeList = attrs;
    PROCESS_INFORMATION pi{};
    DWORD flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
    std::wstring wexe = to_wide(exe);
    BOOL ok = CreateProcessW(wexe.c_str(), cmd.data(), nullptr, nullptr, TRUE, flags, nullptr, nullptr, &si.StartupInfo, &pi);
    DeleteProcThreadAttributeList(attrs);
    if (!ok) return fail("spawn " + o.argv[0]);
    cleanup();
    CloseHandle(pi.hThread);

    auto to_fd = [](HANDLE h, int mode) { return h ? _open_osfhandle(intptr_t(h), mode | _O_BINARY | _O_NOINHERIT) : -1; };
    p.in = to_fd(parent_in, _O_WRONLY);
    p.out = to_fd(parent_out, _O_RDONLY);
    p.err = to_fd(parent_err, _O_RDONLY);
    if (o.detach) {
        CloseHandle(pi.hProcess);
        p.pid = -1;
    } else {
        p.pid = proc_id(pi.hProcess);
    }
    return true;
}

void close_fds(Proc& p) {
    for (int* f : {&p.in, &p.out, &p.err})
        if (*f >= 0) { _close(*f); *f = -1; }
}

int wait_proc(Proc& p) {
    close_fds(p);
    if (p.pid <= 0) return -1;
    HANDLE h = HANDLE(p.pid);
    WaitForSingleObject(h, INFINITE);
    DWORD code = 0;
    bool got = GetExitCodeProcess(h, &code);
    CloseHandle(h);
    p.pid = -1;
    if (!got || code == kKilled) return -1;
    return int(code);
}

void kill_proc(Proc& p) {
    if (p.pid > 0) TerminateProcess(HANDLE(p.pid), kKilled);
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
    std::string o_buf, e_buf;
    std::atomic<bool> too_much{false};
    std::thread to([&] {
        if (!read_all_fd(p.out, o_buf, max_out)) { too_much = true; kill_proc(p); }
    });
    std::thread te([&] { read_all_fd(p.err, e_buf, 65536); });
    if (p.in >= 0) {
        if (!input.empty()) write_all_fd(p.in, input.data(), input.size());
        _close(p.in);
        p.in = -1;
    }
    int result = 0;
    if (timeout_ms > 0 && WaitForSingleObject(HANDLE(p.pid), DWORD(timeout_ms)) == WAIT_TIMEOUT) {
        kill_proc(p);
        result = -3;
    }
    to.join();
    te.join();
    if (too_much) result = -2;
    int rc = wait_proc(p);
    if (out) *out = std::move(o_buf);
    if (err) *err = std::move(e_buf);
    return result != 0 ? result : rc;
}

static bool is_file(const std::string& f) {
    DWORD a = GetFileAttributesW(to_wide(f).c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

std::string find_executable(const std::string& name) {
    if (name.empty()) return "";
    size_t slash = name.find_last_of("/\\"), dot = name.rfind('.');
    bool has_ext = dot != std::string::npos && (slash == std::string::npos || dot > slash);
    auto try_file = [&](const std::string& base) -> std::string {
        if (is_file(base) && has_ext) return base;
        for (const char* e : {".exe", ".com", ".bat", ".cmd"})
            if (is_file(base + e)) return base + e;
        return is_file(base) ? base : "";
    };
    if (name.find_first_of("/\\:") != std::string::npos) return try_file(name);
    const char* path = getenv("PATH");
    for (auto& dir : split(path ? path : "", ';')) {
        if (dir.empty()) continue;
        std::string d = dir;
        if (d.size() > 1 && d.front() == '"' && d.back() == '"') d = d.substr(1, d.size() - 2);
        std::string f = try_file(d + "\\" + name);
        if (!f.empty()) return f;
    }
    return "";
}

}  // namespace s3v
#endif  // _WIN32
