// Desktop trash and zenity/kdialog dialogs (the GUI uses its built-in file browser).
#include <cstdlib>
#include <string>
#include <vector>

#include "platform.h"
#include "util/fs.h"
#include "util/strings.h"
#include "util/subprocess.h"

namespace s3v::platform {

const char* keychain_name() { return "Secret Service (libsecret)"; }
const char* install_gpg_hint() { return "Install gnupg"; }
const char* install_pdf_hint() { return "Install poppler-utils to preview PDFs"; }

// Splits a command line on spaces, honoring simple quotes.
static std::vector<std::string> split_cmd(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    char q = 0;
    bool have = false;
    for (char c : s) {
        if (q) {
            if (c == q) q = 0;
            else cur += c;
        } else if (c == '\'' || c == '"') {
            q = c;
            have = true;
        } else if (c == ' ' || c == '\t') {
            if (have || !cur.empty()) out.push_back(cur);
            cur.clear();
            have = false;
        } else {
            cur += c;
        }
    }
    if (have || !cur.empty()) out.push_back(cur);
    return out;
}

bool trash_local(const std::string& path) {
    if (!find_executable("gio").empty()) {
        std::string err;
        if (run_capture({"gio", "trash", "--", path}, "", nullptr, &err, 4096, 30000) == 0) return true;
    }
    if (!find_executable("trash-put").empty())
        return run_capture({"trash-put", "--", path}, "", nullptr, nullptr, 4096, 30000) == 0;
    return false;
}

static std::vector<std::string> lines(const std::string& s, char sep) {
    std::vector<std::string> r;
    for (auto& l : split(s, sep))
        if (!trim(l).empty()) r.push_back(trim(l));
    return r;
}

std::vector<std::string> pick_files(const std::string& title, bool multiple) {
    std::string out;
    if (!find_executable("zenity").empty()) {
        std::vector<std::string> a = {"zenity", "--file-selection", "--title=" + title};
        if (multiple) { a.push_back("--multiple"); a.push_back("--separator=\n"); }
        if (run_capture(a, "", &out, nullptr, 1 << 20) == 0) return lines(out, '\n');
        return {};
    }
    if (!find_executable("kdialog").empty()) {
        std::vector<std::string> a = {"kdialog", "--title", title, "--getopenfilename", home_dir()};
        if (multiple) a.insert(a.begin() + 3, "--multiple"), a.push_back("--separate-output");
        if (run_capture(a, "", &out, nullptr, 1 << 20) == 0) return lines(out, '\n');
    }
    return {};
}

std::string pick_folder(const std::string& title) {
    std::string out;
    if (!find_executable("zenity").empty()) {
        if (run_capture({"zenity", "--file-selection", "--directory", "--title=" + title}, "", &out, nullptr, 1 << 16) == 0)
            return trim(out);
        return "";
    }
    if (!find_executable("kdialog").empty() &&
        run_capture({"kdialog", "--title", title, "--getexistingdirectory", home_dir()}, "", &out, nullptr, 1 << 16) == 0)
        return trim(out);
    return "";
}

std::string pick_save_path(const std::string& title, const std::string& suggested) {
    std::string out;
    if (!find_executable("zenity").empty()) {
        if (run_capture({"zenity", "--file-selection", "--save", "--confirm-overwrite", "--title=" + title,
                         "--filename=" + home_dir() + "/" + suggested},
                        "", &out, nullptr, 1 << 16) == 0)
            return trim(out);
        return "";
    }
    if (!find_executable("kdialog").empty() &&
        run_capture({"kdialog", "--title", title, "--getsavefilename", home_dir() + "/" + suggested}, "", &out,
                    nullptr, 1 << 16) == 0)
        return trim(out);
    return "";
}

}  // namespace s3v::platform
