// OpenPGP symmetric encryption through the gpg CLI. The passphrase only ever travels on fd 3.
#pragma once
#include <cstdint>
#include <string>
#include <string_view>

#include "util/subprocess.h"

namespace s3v {

enum class CryptoStatus { Ok, BadPassphrase, NotEncrypted, Tampered, TooLarge, Failed };

struct CryptoResult {
    CryptoStatus status = CryptoStatus::Failed;
    std::string detail;
    bool ok() const { return status == CryptoStatus::Ok; }
};

class Gpg {
public:
    // `configured` is "auto" or a path. Empty exe() when gpg is not usable.
    explicit Gpg(const std::string& configured = "auto");
    const std::string& exe() const { return exe_; }
    const std::string& version() const { return version_; }
    bool available() const { return !exe_.empty(); }

    // strong_s2k: iterated+salted S2K at max count (for the password-protected vault key).
    // Otherwise salted S2K (mode 1): only for high-entropy passphrases such as the vault key.
    CryptoResult encrypt_file(const std::string& in_path, const std::string& out_path, std::string_view pass,
                              bool compress, bool strong_s2k = false) const;
    CryptoResult encrypt_string(std::string_view plain, std::string& out, std::string_view pass,
                                bool strong_s2k = false) const;
    CryptoResult decrypt_string(std::string_view cipher, std::string& out, std::string_view pass,
                                size_t max_out = size_t(-1)) const;

    // Push ciphertext in chunks; plaintext goes to a file (out_fd) or memory (capped).
    class Decryptor {
    public:
        ~Decryptor();
        bool write(const char* p, size_t n);  // false once gpg stopped reading
        CryptoResult finish();
        void abort();
        std::string take_output() { return std::move(mem_); }

    private:
        friend class Gpg;
        Proc proc_;
        bool to_memory_ = false;
        size_t max_ = 0;
        std::string mem_;
        std::string status_;
        bool too_large_ = false;
        void* out_thread_ = nullptr;
        void* err_thread_ = nullptr;
        bool finished_ = false;
    };
    // out_fd >= 0: plaintext written there. Otherwise kept in memory up to max_out.
    bool start_decrypt(Decryptor& d, std::string_view pass, int out_fd, size_t max_out = size_t(-1),
                       std::string* error = nullptr) const;

    // Types gpg should not try to compress.
    static bool is_compressed_ext(const std::string& ext);

private:
    std::vector<std::string> base_args() const;
    static CryptoResult classify(int rc, const std::string& status);
    std::string exe_, version_;
};

}  // namespace s3v
