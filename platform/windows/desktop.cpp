// Recycle bin and the common item dialogs (the GUI uses its built-in file browser; these serve the CLI and tools).
#include <windows.h>
#include <shellapi.h>
#include <shobjidl.h>

#include <string>
#include <vector>

#include "platform.h"
#include "util/win_text.h"

namespace s3v::platform {

bool trash_local(const std::string& path) {
    std::wstring from = to_wide(path);
    for (auto& c : from)
        if (c == L'/') c = L'\\';
    from.push_back(L'\0');  // double-NUL terminated list
    SHFILEOPSTRUCTW op{};
    op.wFunc = FO_DELETE;
    op.pFrom = from.c_str();
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    return SHFileOperationW(&op) == 0 && !op.fAnyOperationsAborted;
}

namespace {

struct Com {
    bool ok = SUCCEEDED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE));
    ~Com() { if (ok) CoUninitialize(); }
};

std::string item_path(IShellItem* item) {
    PWSTR p = nullptr;
    std::string r;
    if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &p)) && p) {
        r = slashes(from_wide(p));
        CoTaskMemFree(p);
    }
    return r;
}

std::vector<std::string> open_dialog(const std::string& title, bool folders, bool multiple) {
    Com com;
    std::vector<std::string> out;
    IFileOpenDialog* d = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&d)))) return out;
    DWORD opts = 0;
    d->GetOptions(&opts);
    opts |= FOS_FORCEFILESYSTEM | (folders ? FOS_PICKFOLDERS : 0) | (multiple ? FOS_ALLOWMULTISELECT : 0);
    d->SetOptions(opts);
    d->SetTitle(to_wide(title).c_str());
    if (SUCCEEDED(d->Show(nullptr))) {
        IShellItemArray* items = nullptr;
        if (SUCCEEDED(d->GetResults(&items))) {
            DWORD n = 0;
            items->GetCount(&n);
            for (DWORD i = 0; i < n; i++) {
                IShellItem* it = nullptr;
                if (SUCCEEDED(items->GetItemAt(i, &it))) {
                    std::string p = item_path(it);
                    if (!p.empty()) out.push_back(p);
                    it->Release();
                }
            }
            items->Release();
        }
    }
    d->Release();
    return out;
}

}  // namespace

std::vector<std::string> pick_files(const std::string& title, bool multiple) { return open_dialog(title, false, multiple); }

std::string pick_folder(const std::string& title) {
    auto r = open_dialog(title, true, false);
    return r.empty() ? "" : r[0];
}

std::string pick_save_path(const std::string& title, const std::string& suggested) {
    Com com;
    std::string out;
    IFileSaveDialog* d = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&d)))) return out;
    d->SetTitle(to_wide(title).c_str());
    d->SetFileName(to_wide(suggested).c_str());
    DWORD opts = 0;
    d->GetOptions(&opts);
    d->SetOptions(opts | FOS_FORCEFILESYSTEM | FOS_OVERWRITEPROMPT);
    if (SUCCEEDED(d->Show(nullptr))) {
        IShellItem* it = nullptr;
        if (SUCCEEDED(d->GetResult(&it))) {
            out = item_path(it);
            it->Release();
        }
    }
    d->Release();
    return out;
}

}  // namespace s3v::platform
