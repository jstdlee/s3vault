#include "sync/ignore.h"

#include <fnmatch.h>

#include "util/fs.h"
#include "util/strings.h"

namespace s3v {

IgnoreRules::IgnoreRules() {
    for (const char* p : {".DS_Store", "Thumbs.db", "desktop.ini", "*.swp", "*.swo", "*~", "~$*", ".~lock.*#",
                          "*.s3v-tmp", ".s3vault-*/", ".Trash-*/", "*.part", "*.crdownload"})
        add_pattern(p);
}

void IgnoreRules::add_pattern(const std::string& raw) {
    std::string line = trim(raw);
    if (line.empty() || line[0] == '#') return;
    Rule r;
    if (line[0] == '!') {
        r.negate = true;
        line.erase(0, 1);
    }
    if (!line.empty() && line.back() == '/') {
        r.dir_only = true;
        line.pop_back();
    }
    if (!line.empty() && line[0] == '/') {
        r.anchored = true;
        line.erase(0, 1);
    } else if (line.find('/') != std::string::npos) {
        r.anchored = true;
    }
    if (line.empty()) return;
    r.pat = line;
    rules_.push_back(r);
}

void IgnoreRules::load_file(const std::string& path) {
    std::string data;
    if (!read_file(path, data, 1 << 20)) return;
    for (auto& l : split(data, '\n')) add_pattern(l);
}

static bool match_anchored(const std::string& pat, const std::string& path) {
    if (fnmatch(pat.c_str(), path.c_str(), FNM_PATHNAME) == 0) return true;
    // "**/" matches zero or more directories.
    size_t pos = pat.find("**/");
    if (pos != std::string::npos) {
        std::string head = pat.substr(0, pos), tail = pat.substr(pos + 3);
        if (!head.empty() && !starts_with(path, head)) return false;
        std::string rest = path.substr(head.size());
        for (size_t i = 0;; ) {
            if (match_anchored(tail, rest.substr(i))) return true;
            size_t sl = rest.find('/', i);
            if (sl == std::string::npos) break;
            i = sl + 1;
        }
    }
    if (ends_with(pat, "/**")) return starts_with(path, pat.substr(0, pat.size() - 2));
    return false;
}

bool IgnoreRules::ignored(const std::string& rel, bool is_dir) const {
    // A path is ignored if it or any parent directory is ignored (last matching rule wins per level).
    auto parts = split(rel, '/');
    std::string prefix;
    for (size_t i = 0; i < parts.size(); i++) {
        prefix = prefix.empty() ? parts[i] : prefix + "/" + parts[i];
        bool dir = i + 1 < parts.size() || is_dir;
        bool ign = false;
        for (auto& r : rules_) {
            if (r.dir_only && !dir) continue;
            bool m = r.anchored ? match_anchored(r.pat, prefix) : fnmatch(r.pat.c_str(), parts[i].c_str(), 0) == 0;
            if (m) ign = !r.negate;
        }
        if (ign) return true;
    }
    return false;
}

}  // namespace s3v
