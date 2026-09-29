#include "secret/passcache.h"

#include <ctime>

namespace s3v {

static int64_t now_s() { return int64_t(time(nullptr)); }

PassCache::Mode PassCache::parse_mode(const std::string& s) {
    if (s == "ask") return Mode::Ask;
    if (s == "session") return Mode::Session;
    if (s == "keychain") return Mode::Keychain;
    return Mode::Idle;
}

void PassCache::set(std::string_view key) {
    std::lock_guard<std::mutex> lk(mu_);
    key_.assign(key);
    last_use_ = now_s();
    expired_flag_ = false;
}

SecureString PassCache::get() {
    std::lock_guard<std::mutex> lk(mu_);
    if (key_.empty()) return {};
    if (mode_ == Mode::Idle && idle_s_ > 0 && now_s() - last_use_ > idle_s_) {
        key_.clear();
        expired_flag_ = true;
        return {};
    }
    last_use_ = now_s();
    return key_;
}

bool PassCache::unlocked() {
    std::lock_guard<std::mutex> lk(mu_);
    return !key_.empty();
}

void PassCache::lock() {
    std::lock_guard<std::mutex> lk(mu_);
    key_.clear();
}

bool PassCache::tick() {
    std::lock_guard<std::mutex> lk(mu_);
    if (!key_.empty() && mode_ == Mode::Idle && idle_s_ > 0 && now_s() - last_use_ > idle_s_) {
        key_.clear();
        expired_flag_ = true;
    }
    bool f = expired_flag_;
    expired_flag_ = false;
    return f;
}

int64_t PassCache::seconds_left() {
    std::lock_guard<std::mutex> lk(mu_);
    if (key_.empty() || mode_ != Mode::Idle || idle_s_ <= 0) return -1;
    int64_t left = idle_s_ - (now_s() - last_use_);
    return left < 0 ? 0 : left;
}

void PassCache::release_if_ask() {
    std::lock_guard<std::mutex> lk(mu_);
    if (mode_ == Mode::Ask) key_.clear();
}

}  // namespace s3v
