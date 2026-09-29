// gitignore-style rules: built-in defaults + <root>/.s3vaultignore.
#pragma once
#include <string>
#include <vector>

namespace s3v {

class IgnoreRules {
public:
    IgnoreRules();  // built-in defaults only
    void add_pattern(const std::string& line);
    void load_file(const std::string& path);  // missing file is fine
    // rel is '/'-separated, relative to the root.
    bool ignored(const std::string& rel, bool is_dir) const;

private:
    struct Rule {
        std::string pat;
        bool negate = false;
        bool dir_only = false;
        bool anchored = false;  // contains '/' → matched against the whole path
    };
    std::vector<Rule> rules_;
};

}  // namespace s3v
