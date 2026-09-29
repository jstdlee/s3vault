// ~/.config/s3vault/config.ini — no secrets in here.
#pragma once
#include <map>
#include <string>

namespace s3v {

struct StorageConfig {
    std::string provider = "r2";      // aws | r2 | minio | b2 | wasabi | custom
    std::string account_id;           // r2 only
    std::string endpoint = "auto";    // https://host[:port]
    std::string region = "auto";
    std::string addressing = "auto";  // path | virtual
    std::string bucket;
    std::string prefix = "s3vault/main";
    std::string access_key_id;
};

struct DepsConfig {
    std::string gpg = "auto";
    std::string pdftoppm = "auto";
    std::string opener = "xdg-open";
    std::string editor = "auto";
    std::string terminal = "x-terminal-emulator -e";
};

struct SecurityConfig {
    std::string remember = "idle";  // ask | session | idle | keychain
    int idle_minutes = 15;
    int keychain_days = 7;
    int min_length = 14;
};

struct PreviewConfig {
    int text_max_mb = 2;
    int image_max_mb = 50;
    int image_max_mpix = 64;
    int pdf_max_mb = 100;
    int pdf_dpi = 110;
    int idle_free_seconds = 120;
};

struct SyncConfig {
    int poll_seconds = 60;
    int rescan_minutes = 10;
    int concurrency = 8;
    int bandwidth_kbps = 0;
    int trash_days = 30;
    std::string device_name;  // defaults to hostname
};

struct UiConfig {
    std::string columns = "name,type,size,modified,status";
    std::string sort = "name:asc";
    int width = 1100, height = 720;
    float font_size = 15.0f;
};

struct Config {
    StorageConfig storage;
    DepsConfig deps;
    SecurityConfig security;
    PreviewConfig preview;
    SyncConfig sync;
    UiConfig ui;

    bool load(const std::string& path);
    bool save(const std::string& path) const;
    // Key/value access for the CLI (`s3vault-cli config set storage.bucket x`).
    bool set(const std::string& dotted_key, const std::string& value);
    std::map<std::string, std::string> dump() const;
    std::string device() const;
};

// $S3VAULT_HOME/config.ini or ~/.config/s3vault/config.ini
std::string config_dir();
std::string config_path();
// $S3VAULT_HOME/data or ~/.local/share/s3vault
std::string data_dir();

}  // namespace s3v
