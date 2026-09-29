// SHA-256 and HMAC-SHA256 (FIPS 180-4 / RFC 2104). Used for SigV4 and content hashes.
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace s3v {

class Sha256 {
public:
    Sha256();
    void update(const void* data, size_t len);
    void update(std::string_view s) { update(s.data(), s.size()); }
    void final(uint8_t out[32]);
    std::string hex();  // finalizes

private:
    void block(const uint8_t* p);
    uint32_t h_[8];
    uint8_t buf_[64];
    size_t buf_len_ = 0;
    uint64_t total_ = 0;
};

std::string sha256_hex(std::string_view data);
std::string sha256_raw(std::string_view data);  // 32 raw bytes
std::string hmac_sha256_raw(std::string_view key, std::string_view msg);
std::string to_hex(std::string_view raw);

// Hex SHA-256 of a file's contents; empty string on read error.
std::string sha256_file(const std::string& path);

}  // namespace s3v
