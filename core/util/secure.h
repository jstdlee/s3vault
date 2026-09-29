// Secrets in locked, zeroed-on-free memory.
#pragma once
#include <cstddef>
#include <string>
#include <string_view>

namespace s3v {

class SecureString {
public:
    SecureString() = default;
    explicit SecureString(std::string_view s) { assign(s); }
    SecureString(const SecureString& o) { assign(o.view()); }
    SecureString& operator=(const SecureString& o) { if (this != &o) assign(o.view()); return *this; }
    SecureString(SecureString&& o) noexcept : p_(o.p_), n_(o.n_), cap_(o.cap_) { o.p_ = nullptr; o.n_ = o.cap_ = 0; }
    SecureString& operator=(SecureString&& o) noexcept;
    ~SecureString() { clear(); }

    void assign(std::string_view s);
    void clear();
    bool empty() const { return n_ == 0; }
    size_t size() const { return n_; }
    std::string_view view() const { return {p_ ? p_ : "", n_}; }

private:
    char* p_ = nullptr;
    size_t n_ = 0, cap_ = 0;
};

// Overwrite a std::string's buffer before dropping it.
void wipe(std::string& s);
// Cryptographically random bytes (getrandom).
std::string random_bytes(size_t n);

}  // namespace s3v
