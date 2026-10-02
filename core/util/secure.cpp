#include "util/secure.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/mman.h>
#include <sys/random.h>
#endif

#include <cerrno>
#include <cstdlib>
#include <cstring>

namespace s3v {

#ifdef _WIN32
static void mlock(void* p, size_t n) { VirtualLock(p, n); }
static void munlock(void* p, size_t n) { VirtualUnlock(p, n); }
static long getrandom(void* p, size_t n, int) {
    ULONG k = ULONG(n > 1u << 20 ? 1u << 20 : n);
    return BCryptGenRandom(nullptr, static_cast<PUCHAR>(p), k, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? long(k) : -1;
}
#endif

SecureString& SecureString::operator=(SecureString&& o) noexcept {
    if (this != &o) {
        clear();
        p_ = o.p_; n_ = o.n_; cap_ = o.cap_;
        o.p_ = nullptr; o.n_ = o.cap_ = 0;
    }
    return *this;
}

void SecureString::assign(std::string_view s) {
    clear();
    if (s.empty()) return;
    cap_ = s.size() + 1;
    p_ = static_cast<char*>(malloc(cap_));
    if (!p_) { cap_ = 0; return; }
    mlock(p_, cap_);  // best effort; keeps the key out of swap
    memcpy(p_, s.data(), s.size());
    p_[s.size()] = 0;
    n_ = s.size();
}

void SecureString::clear() {
    if (p_) {
        secure_zero(p_, cap_);
        munlock(p_, cap_);
        free(p_);
    }
    p_ = nullptr;
    n_ = cap_ = 0;
}

void secure_zero(void* p, size_t n) {
#ifdef _WIN32
    SecureZeroMemory(p, n);
#else
    explicit_bzero(p, n);
#endif
}

void wipe(std::string& s) {
    if (!s.empty()) secure_zero(s.data(), s.size());
    s.clear();
    s.shrink_to_fit();
}

std::string random_bytes(size_t n) {
    std::string r(n, '\0');
    size_t got = 0;
    while (got < n) {
        long k = long(getrandom(r.data() + got, n - got, 0));
        if (k < 0) {
            if (errno == EINTR) continue;
            abort();  // no safe fallback for key material
        }
        got += size_t(k);
    }
    return r;
}

}  // namespace s3v
