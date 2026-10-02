// Secrets in the Windows Credential Manager (per-user, protected by DPAPI). Generic credentials named
// "s3vault:<account>"; the blob is "<expires>:<secret>" so expiry is enforced on read, as on Linux.
#include <windows.h>
#include <wincred.h>

#include <cstdlib>
#include <ctime>
#include <string>

#include "platform.h"
#include "util/secure.h"
#include "util/win_text.h"

namespace s3v::platform {

static std::wstring target(const std::string& account) { return to_wide("s3vault:" + account); }

void keychain_preload() {}

bool keychain_available() { return true; }

bool keychain_store(const std::string& account, std::string_view secret, int64_t expires_unix) {
    std::string value = std::to_string(expires_unix) + ":" + std::string(secret);
    std::wstring t = target(account);
    std::wstring user = L"s3vault";
    CREDENTIALW c{};
    c.Type = CRED_TYPE_GENERIC;
    c.TargetName = t.data();
    c.CredentialBlobSize = DWORD(value.size());
    c.CredentialBlob = reinterpret_cast<LPBYTE>(value.data());
    c.Persist = CRED_PERSIST_LOCAL_MACHINE;  // this user on this machine; never roams
    c.UserName = user.data();
    bool ok = CredWriteW(&c, 0) != 0;
    wipe(value);
    return ok;
}

bool keychain_load(const std::string& account, SecureString& out) {
    PCREDENTIALW c = nullptr;
    if (!CredReadW(target(account).c_str(), CRED_TYPE_GENERIC, 0, &c)) return false;
    std::string_view sv(reinterpret_cast<const char*>(c->CredentialBlob), c->CredentialBlobSize);
    size_t colon = sv.find(':');
    bool ok = false;
    if (colon != std::string_view::npos) {
        int64_t exp = atoll(std::string(sv.substr(0, colon)).c_str());
        if (exp == 0 || exp > int64_t(time(nullptr))) {
            out.assign(sv.substr(colon + 1));
            ok = true;
        }
    }
    SecureZeroMemory(c->CredentialBlob, c->CredentialBlobSize);
    CredFree(c);
    if (!ok) keychain_erase(account);
    return ok;
}

bool keychain_erase(const std::string& account) { return CredDeleteW(target(account).c_str(), CRED_TYPE_GENERIC, 0) != 0; }

}  // namespace s3v::platform
