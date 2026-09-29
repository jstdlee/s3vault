// Password strength estimate (length, classes, patterns, common passwords) and a generator.
#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace s3v {

struct Strength {
    int score = 0;       // 0..4; ≥ 3 accepted
    double bits = 0;     // rough entropy estimate
    std::vector<std::string> problems;
    bool acceptable = false;
};

Strength check_password(std::string_view pw, int min_length = 14);
// 6 groups of 4 unambiguous characters (≈120 bits), e.g. "k7qm-2hxw-…".
std::string generate_password();

}  // namespace s3v
