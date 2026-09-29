#include "util/secure.h"

#include <sys/mman.h>
#include <sys/random.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>

namespace s3v {

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
        explicit_bzero(p_, cap_);
        munlock(p_, cap_);
        free(p_);
    }
    p_ = nullptr;
    n_ = cap_ = 0;
}

void wipe(std::string& s) {
    if (!s.empty()) explicit_bzero(s.data(), s.size());
    s.clear();
    s.shrink_to_fit();
}

std::string random_bytes(size_t n) {
    std::string r(n, '\0');
    size_t got = 0;
    while (got < n) {
        ssize_t k = getrandom(r.data() + got, n - got, 0);
        if (k < 0) {
            if (errno == EINTR) continue;
            abort();  // no safe fallback for key material
        }
        got += size_t(k);
    }
    return r;
}

}  // namespace s3v
