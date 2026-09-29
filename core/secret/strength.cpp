#include "secret/strength.h"

#include <cctype>
#include <cmath>
#include <set>

#include "util/secure.h"
#include "util/strings.h"

namespace s3v {

static const char* kCommon[] = {
    "password", "passw0rd", "123456", "qwerty", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon",
    "football", "baseball", "sunshine", "princess", "master", "shadow", "superman", "michael", "trustno1",
    "starwars", "whatever", "freedom", "abc123", "111111", "000000", "secret", "s3vault", "changeme", "qazwsx",
    "asdfgh", "zxcvbn", "hello", "login", "default"};

// Longest run of characters that follow a keyboard row or the alphabet/digits (either direction).
static size_t longest_seq(std::string_view s) {
    static const char* rows[] = {"qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz"};
    std::string l = to_lower(s);
    size_t best = 0;
    for (size_t i = 0; i < l.size(); i++) {
        for (size_t len = l.size() - i; len >= 3 && len > best; len--) {
            std::string w = l.substr(i, len);
            bool hit = false;
            for (auto* r : rows) {
                std::string row(r), rev(row.rbegin(), row.rend());
                if (row.find(w) != std::string::npos || rev.find(w) != std::string::npos) { hit = true; break; }
            }
            if (hit) { best = len; break; }
        }
    }
    return best;
}

Strength check_password(std::string_view pw, int min_length) {
    Strength s;
    bool lo = false, up = false, dg = false, sy = false, other = false;
    for (unsigned char c : pw) {
        if (c >= 128) other = true;
        else if (islower(c)) lo = true;
        else if (isupper(c)) up = true;
        else if (isdigit(c)) dg = true;
        else sy = true;
    }
    int classes = lo + up + dg + sy + other;
    double pool = (lo ? 26 : 0) + (up ? 26 : 0) + (dg ? 10 : 0) + (sy ? 33 : 0) + (other ? 100 : 0);
    // Count distinct characters: "aaaaaaaaaaaaaa" is not 14 characters of entropy.
    std::set<unsigned char> distinct(pw.begin(), pw.end());
    double effective_len = std::min<double>(double(pw.size()), double(distinct.size()) * 1.5);
    s.bits = pool > 0 ? effective_len * std::log2(pool) : 0;

    if (int(pw.size()) < min_length) s.problems.push_back("at least " + std::to_string(min_length) + " characters");
    if (classes < 2) s.problems.push_back("mix character types (letters, digits, symbols)");
    if (distinct.size() < pw.size() / 2) s.problems.push_back("too many repeated characters");
    std::string l = to_lower(pw);
    for (auto* c : kCommon)
        if (l.find(c) != std::string::npos) {
            s.problems.push_back(std::string("contains a common word (\"") + c + "\")");
            s.bits -= 20;
            break;
        }
    size_t seq = longest_seq(pw);
    if (seq >= 4) {
        s.bits -= double(seq) * 3;
        if (seq * 3 >= pw.size()) s.problems.push_back("mostly a sequence like abcd / 1234 / qwer");
    }
    if (s.bits < 0) s.bits = 0;
    s.score = s.bits < 28 ? 0 : s.bits < 45 ? 1 : s.bits < 60 ? 2 : s.bits < 80 ? 3 : 4;
    s.acceptable = s.problems.empty() && s.score >= 3;
    if (s.problems.empty() && s.score < 3) s.problems.push_back("too predictable; make it longer");
    return s;
}

std::string generate_password() {
    static const char* alpha = "abcdefghjkmnpqrstuvwxyz23456789";  // 31 unambiguous chars
    std::string r;
    for (int g = 0; g < 6; g++) {
        if (g) r += '-';
        for (int i = 0; i < 4; i++) {
            unsigned char b;
            do b = static_cast<unsigned char>(random_bytes(1)[0]); while (b >= 248);  // 248 = 8 * 31: no modulo bias
            r += alpha[b % 31];
        }
    }
    // One capital so every class-based policy elsewhere is satisfied too.
    r[0] = char(toupper(static_cast<unsigned char>(r[0])));
    return r;
}

}  // namespace s3v
