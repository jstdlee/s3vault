// Per-process directory for decrypted plaintext: %LOCALAPPDATA%\s3vault\tmp\<pid>. Windows has no tmpfs, so files
// are overwritten before they are deleted. The folder lives in the user's profile, readable only by that user.
#include <windows.h>

#include <dirent.h>

#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>

#include "platform.h"
#include "util/compat.h"
#include "util/fs.h"
#include "util/win_text.h"

namespace s3v::platform {

static std::string base_dir() {
    const wchar_t* l = _wgetenv(L"LOCALAPPDATA");
    std::string b = l && *l ? slashes(from_wide(l)) : home_dir() + "/AppData/Local";
    return b + "/s3vault/tmp";
}

static std::string own_dir() { return base_dir() + "/" + std::to_string(GetCurrentProcessId()); }

std::string session_tmp_dir() {
    static std::mutex mu;
    std::lock_guard<std::mutex> lk(mu);
    std::string d = own_dir();
    if (!stat_path(d, true).is_dir) mkdirs(d, 0700);
    return d;
}

bool session_tmp_in_ram() { return false; }

void wipe_session_tmp() { remove_tree(own_dir(), true); }

static bool s3vault_running(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    wchar_t buf[MAX_PATH * 4];
    DWORD n = DWORD(sizeof buf / sizeof buf[0]);
    bool ours = false;
    DWORD code = 0;
    if (GetExitCodeProcess(h, &code) && code == STILL_ACTIVE && QueryFullProcessImageNameW(h, 0, buf, &n))
        ours = from_wide(buf, int(n)).find("s3vault") != std::string::npos;
    CloseHandle(h);
    return ours;
}

int cleanup_stale_tmp() {
    std::string b = base_dir();
    int n = 0;
    DIR* dir = opendir(b.c_str());
    if (!dir) return 0;
    while (dirent* e = readdir(dir)) {
        char* end = nullptr;
        long pid = strtol(e->d_name, &end, 10);
        if (!end || *end || pid <= 0 || DWORD(pid) == GetCurrentProcessId()) continue;
        if (s3vault_running(DWORD(pid))) continue;  // another s3vault instance
        remove_tree(b + "/" + e->d_name, true);
        n++;
    }
    closedir(dir);
    return n;
}

static std::function<void()>* g_extra = nullptr;

static BOOL WINAPI on_console_event(DWORD) {
    if (g_extra && *g_extra) (*g_extra)();
    wipe_session_tmp();
    return FALSE;  // let the default handler end the process
}

void install_exit_cleanup(std::function<void()> extra) {
    static std::function<void()> keep;
    keep = std::move(extra);
    g_extra = &keep;
    SetConsoleCtrlHandler(on_console_event, TRUE);
    atexit([] { wipe_session_tmp(); });
}

}  // namespace s3v::platform
