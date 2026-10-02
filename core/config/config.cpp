#include "config/config.h"

#include "util/compat.h"
#ifdef _WIN32
#include "util/win_text.h"
#endif

#include <cstdlib>
#include <sstream>
#include <vector>

#include "util/fs.h"
#include "util/strings.h"

namespace s3v {

namespace {

struct Field {
    const char* key;
    std::string* s = nullptr;
    int* i = nullptr;
    float* f = nullptr;
};

std::vector<Field> fields(Config& c) {
    return {
        {"storage.provider", &c.storage.provider},
        {"storage.account_id", &c.storage.account_id},
        {"storage.endpoint", &c.storage.endpoint},
        {"storage.region", &c.storage.region},
        {"storage.addressing", &c.storage.addressing},
        {"storage.bucket", &c.storage.bucket},
        {"storage.prefix", &c.storage.prefix},
        {"storage.access_key_id", &c.storage.access_key_id},
        {"deps.gpg", &c.deps.gpg},
        {"deps.pdftoppm", &c.deps.pdftoppm},
        {"security.remember", &c.security.remember},
        {"security.idle_minutes", nullptr, &c.security.idle_minutes},
        {"security.keychain_days", nullptr, &c.security.keychain_days},
        {"security.min_length", nullptr, &c.security.min_length},
        {"preview.text_max_mb", nullptr, &c.preview.text_max_mb},
        {"preview.image_max_mb", nullptr, &c.preview.image_max_mb},
        {"preview.image_max_mpix", nullptr, &c.preview.image_max_mpix},
        {"preview.pdf_max_mb", nullptr, &c.preview.pdf_max_mb},
        {"preview.pdf_dpi", nullptr, &c.preview.pdf_dpi},
        {"preview.idle_free_seconds", nullptr, &c.preview.idle_free_seconds},
        {"sync.poll_seconds", nullptr, &c.sync.poll_seconds},
        {"sync.rescan_minutes", nullptr, &c.sync.rescan_minutes},
        {"sync.concurrency", nullptr, &c.sync.concurrency},
        {"sync.bandwidth_kbps", nullptr, &c.sync.bandwidth_kbps},
        {"sync.trash_days", nullptr, &c.sync.trash_days},
        {"sync.device_name", &c.sync.device_name},
        {"ui.columns", &c.ui.columns},
        {"ui.sort", &c.ui.sort},
        {"ui.width", nullptr, &c.ui.width},
        {"ui.height", nullptr, &c.ui.height},
        {"ui.font_size", nullptr, nullptr, &c.ui.font_size},
        {"ui.theme", &c.ui.theme},
        {"ui.inspector", nullptr, &c.ui.inspector},
        {"ui.advanced", nullptr, &c.ui.advanced},
    };
}

}  // namespace

bool Config::set(const std::string& key, const std::string& value) {
    for (auto& f : fields(*this)) {
        if (key != f.key) continue;
        if (f.s) *f.s = value;
        if (f.i) *f.i = atoi(value.c_str());
        if (f.f) *f.f = float(atof(value.c_str()));
        return true;
    }
    return false;
}

std::map<std::string, std::string> Config::dump() const {
    std::map<std::string, std::string> m;
    for (auto& f : fields(const_cast<Config&>(*this))) {
        if (f.s) m[f.key] = *f.s;
        if (f.i) m[f.key] = std::to_string(*f.i);
        if (f.f) {
            std::ostringstream o;
            o << *f.f;
            m[f.key] = o.str();
        }
    }
    return m;
}

bool Config::load(const std::string& path) {
    std::string data;
    if (!read_file(path, data)) return false;
    std::string section;
    for (auto& raw : split(data, '\n')) {
        std::string line = trim(raw);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        if (line.front() == '[' && line.back() == ']') {
            section = trim(line.substr(1, line.size() - 2));
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = trim(line.substr(0, eq));
        std::string v = line.substr(eq + 1);
        // Strip trailing "; comment" (values never contain " ;").
        if (size_t c = v.find(" ;"); c != std::string::npos) v = v.substr(0, c);
        set(section + "." + k, trim(v));
    }
    return true;
}

bool Config::save(const std::string& path) const {
    std::ostringstream o;
    o << "; s3vault configuration. Secrets (S3 secret key, password) are never stored here.\n";
    std::string section;
    for (auto& f : fields(const_cast<Config&>(*this))) {
        std::string key = f.key;
        size_t dot = key.find('.');
        std::string sec = key.substr(0, dot);
        if (sec != section) {
            o << (section.empty() ? "" : "\n") << "[" << sec << "]\n";
            section = sec;
        }
        o << key.substr(dot + 1) << " = ";
        if (f.s) o << *f.s;
        if (f.i) o << *f.i;
        if (f.f) o << *f.f;
        o << "\n";
    }
    mkdirs(path_dirname(path), 0700);
    return write_file_atomic(path, o.str(), 0600);
}

std::string Config::device() const {
    if (!sync.device_name.empty()) return sync.device_name;
#ifdef _WIN32
    wchar_t w[256] = {};
    DWORD n = 255;
    std::string h = GetComputerNameExW(ComputerNamePhysicalDnsHostname, w, &n) ? from_wide(w, int(n)) : "";
    return h.empty() ? "device" : h;
#else
    char h[256] = {};
    gethostname(h, sizeof h - 1);
    return h[0] ? h : "device";
#endif
}

std::string config_dir() {
    if (const char* h = getenv("S3VAULT_HOME"); h && *h) return h;
#ifdef _WIN32
    if (const wchar_t* a = _wgetenv(L"APPDATA"); a && *a) return slashes(from_wide(a)) + "/s3vault";
#endif
    const char* x = getenv("XDG_CONFIG_HOME");
    return std::string(x && *x ? x : (home_dir() + "/.config")) + "/s3vault";
}

std::string config_path() { return config_dir() + "/config.ini"; }

std::string data_dir() {
    if (const char* h = getenv("S3VAULT_HOME"); h && *h) return std::string(h) + "/data";
#ifdef _WIN32
    if (const wchar_t* a = _wgetenv(L"LOCALAPPDATA"); a && *a) return slashes(from_wide(a)) + "/s3vault";
#endif
    const char* x = getenv("XDG_DATA_HOME");
    return std::string(x && *x ? x : (home_dir() + "/.local/share")) + "/s3vault";
}

}  // namespace s3v
