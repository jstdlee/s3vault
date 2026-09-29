// Holds the unlocked vault key in locked memory for as long as the configured policy allows.
#pragma once
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>

#include "util/secure.h"

namespace s3v {

class PassCache {
public:
    enum class Mode { Ask, Session, Idle, Keychain };
    static Mode parse_mode(const std::string& s);

    void configure(Mode m, int idle_minutes) {
        std::lock_guard<std::mutex> lk(mu_);
        mode_ = m;
        idle_s_ = idle_minutes * 60;
    }
    void set(std::string_view key);
    // Returns the key (and refreshes the idle timer). Empty when locked.
    SecureString get();
    bool unlocked();
    void lock();
    // Call periodically; returns true exactly once when the key has just expired.
    bool tick();
    // Seconds until the idle lock (-1 if none).
    int64_t seconds_left();
    // Ask mode: the key is kept only for the duration of one operation; callers call release() afterwards.
    void release_if_ask();
    Mode mode() { std::lock_guard<std::mutex> lk(mu_); return mode_; }

private:
    std::mutex mu_;
    Mode mode_ = Mode::Idle;
    int64_t idle_s_ = 15 * 60;
    int64_t last_use_ = 0;
    SecureString key_;
    bool expired_flag_ = false;
};

}  // namespace s3v
