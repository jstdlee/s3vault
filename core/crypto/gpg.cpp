#include "crypto/gpg.h"

#include <fcntl.h>
#include <unistd.h>

#include <thread>

#include "util/secure.h"
#include "util/strings.h"

namespace s3v {

Gpg::Gpg(const std::string& configured) {
    std::string exe = find_executable(configured.empty() || configured == "auto" ? "gpg" : configured);
    if (exe.empty() && (configured.empty() || configured == "auto")) exe = find_executable("gpg2");
    if (exe.empty()) return;
    std::string out;
    if (run_capture({exe, "--version"}, "", &out, nullptr, 1 << 16, 5000) != 0) return;
    // "gpg (GnuPG) 2.4.4"
    std::string first = out.substr(0, out.find('\n'));
    version_ = first.substr(first.rfind(' ') + 1);
    int major = atoi(version_.c_str());
    int minor = atoi(version_.c_str() + (version_.find('.') == std::string::npos ? 0 : version_.find('.') + 1));
    if (major < 2 || (major == 2 && minor < 2)) {
        version_ += " (too old, need ≥ 2.2)";
        return;
    }
    exe_ = exe;
}

std::vector<std::string> Gpg::base_args() const {
    return {exe_, "--batch", "--quiet", "--no-tty", "--no-greeting", "--no-symkey-cache",
            "--pinentry-mode", "loopback", "--passphrase-fd", "3", "--status-fd", "2"};
}

bool Gpg::is_compressed_ext(const std::string& e) {
    static const char* list[] = {"jpg", "jpeg", "png", "gif", "webp", "heic", "avif", "mp3", "m4a", "aac", "ogg",
                                 "opus", "flac", "mp4", "mkv", "mov", "webm", "avi", "zip", "gz", "tgz", "bz2",
                                 "xz", "zst", "7z", "rar", "pdf", "docx", "xlsx", "pptx", "odt", "epub", "jar",
                                 "apk", "deb", "rpm", "dmg", "iso"};
    for (auto* x : list)
        if (e == x) return true;
    return false;
}

CryptoResult Gpg::classify(int rc, const std::string& status) {
    CryptoResult r;
    auto has = [&](const char* s) { return status.find(s) != std::string::npos; };
    if (has("[GNUPG:] DECRYPTION_FAILED") && (has("BAD_PASSPHRASE") || has("Bad session key"))) {
        r.status = CryptoStatus::BadPassphrase;
        r.detail = "wrong password or key";
    } else if (has("BAD_PASSPHRASE") || has("Bad session key")) {
        r.status = CryptoStatus::BadPassphrase;
        r.detail = "wrong password or key";
    } else if (has("[GNUPG:] DECRYPTION_FAILED") || has("manipulated") || has("BADMDC")) {
        r.status = CryptoStatus::Tampered;
        r.detail = "decryption failed (damaged or modified data)";
    } else if (rc != 0) {
        r.status = CryptoStatus::Failed;
        // Last non-status line of stderr is the most useful message.
        std::string msg;
        for (auto& l : split(status, '\n'))
            if (!l.empty() && !starts_with(l, "[GNUPG:]")) msg = l;
        r.detail = msg.empty() ? "gpg exited with " + std::to_string(rc) : msg;
    } else {
        r.status = CryptoStatus::Ok;
    }
    return r;
}

CryptoResult Gpg::encrypt_file(const std::string& in_path, const std::string& out_path, std::string_view pass,
                               bool compress, bool strong_s2k) const {
    CryptoResult r;
    if (!available()) { r.detail = "gpg not found"; return r; }
    int in = open(in_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (in < 0) { r.detail = "cannot read " + in_path; return r; }
    int out = open(out_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (out < 0) { close(in); r.detail = "cannot write " + out_path; return r; }
    SpawnOpts o;
    o.argv = base_args();
    for (const char* a : {"--symmetric", "--cipher-algo", "AES256", "--s2k-digest-algo", "SHA512", "--set-filename", ""})
        o.argv.push_back(a);
    if (strong_s2k) for (const char* a : {"--s2k-mode", "3", "--s2k-count", "65011712"}) o.argv.push_back(a);
    else for (const char* a : {"--s2k-mode", "1"}) o.argv.push_back(a);
    if (!compress) for (const char* a : {"--compress-algo", "none"}) o.argv.push_back(a);
    o.argv.push_back("-o");
    o.argv.push_back("-");
    o.stdin_fd = in;
    o.stdout_fd = out;
    o.pipe_stderr = true;
    o.has_fd3 = true;
    o.fd3_data = std::string(pass) + "\n";
    Proc p;
    std::string err;
    bool started = spawn(o, p, &err);
    wipe(o.fd3_data);
    close(in);
    close(out);
    if (!started) { r.detail = err; return r; }
    std::string status;
    read_all_fd(p.err, status, 1 << 20);
    int rc = wait_proc(p);
    r = classify(rc, status);
    return r;
}

CryptoResult Gpg::encrypt_string(std::string_view plain, std::string& out, std::string_view pass,
                                 bool strong_s2k) const {
    CryptoResult r;
    if (!available()) { r.detail = "gpg not found"; return r; }
    SpawnOpts o;
    o.argv = base_args();
    for (const char* a : {"--symmetric", "--cipher-algo", "AES256", "--s2k-digest-algo", "SHA512", "--set-filename", ""})
        o.argv.push_back(a);
    if (strong_s2k) for (const char* a : {"--s2k-mode", "3", "--s2k-count", "65011712"}) o.argv.push_back(a);
    else for (const char* a : {"--s2k-mode", "1"}) o.argv.push_back(a);
    o.argv.push_back("-o");
    o.argv.push_back("-");
    o.pipe_stdin = o.pipe_stdout = o.pipe_stderr = true;
    o.has_fd3 = true;
    o.fd3_data = std::string(pass) + "\n";
    Proc p;
    std::string err;
    bool started = spawn(o, p, &err);
    wipe(o.fd3_data);
    if (!started) { r.detail = err; return r; }
    std::string status;
    std::thread te([&] { read_all_fd(p.err, status, 1 << 20); });
    std::thread to([&] { read_all_fd(p.out, out); });
    write_all_fd(p.in, plain.data(), plain.size());
    close(p.in);
    p.in = -1;
    to.join();
    te.join();
    return classify(wait_proc(p), status);
}

CryptoResult Gpg::decrypt_string(std::string_view cipher, std::string& out, std::string_view pass,
                                 size_t max_out) const {
    Decryptor d;
    std::string err;
    if (!start_decrypt(d, pass, -1, max_out, &err)) {
        CryptoResult r;
        r.detail = err;
        return r;
    }
    d.write(cipher.data(), cipher.size());
    CryptoResult r = d.finish();
    out = d.take_output();
    return r;
}

bool Gpg::start_decrypt(Decryptor& d, std::string_view pass, int out_fd, size_t max_out, std::string* error) const {
    if (!available()) {
        if (error) *error = "gpg not found";
        return false;
    }
    SpawnOpts o;
    o.argv = base_args();
    o.argv.push_back("--decrypt");
    o.pipe_stdin = true;
    o.pipe_stderr = true;
    if (out_fd >= 0) o.stdout_fd = out_fd;
    else o.pipe_stdout = true;
    o.has_fd3 = true;
    o.fd3_data = std::string(pass) + "\n";
    bool ok = spawn(o, d.proc_, error);
    wipe(o.fd3_data);
    if (!ok) return false;
    d.to_memory_ = out_fd < 0;
    d.max_ = max_out;
    d.err_thread_ = new std::thread([&d] { read_all_fd(d.proc_.err, d.status_, 1 << 20); });
    if (d.to_memory_) {
        d.out_thread_ = new std::thread([&d] {
            if (!read_all_fd(d.proc_.out, d.mem_, d.max_)) {
                d.too_large_ = true;
                kill_proc(d.proc_);
            }
        });
    }
    return true;
}

bool Gpg::Decryptor::write(const char* p, size_t n) {
    if (proc_.in < 0 || too_large_) return false;
    if (!write_all_fd(proc_.in, p, n)) {
        close(proc_.in);
        proc_.in = -1;
        return false;
    }
    return true;
}

static void join_del(void*& t) {
    if (!t) return;
    auto* th = static_cast<std::thread*>(t);
    th->join();
    delete th;
    t = nullptr;
}

CryptoResult Gpg::Decryptor::finish() {
    if (proc_.in >= 0) { close(proc_.in); proc_.in = -1; }
    join_del(out_thread_);
    join_del(err_thread_);
    finished_ = true;
    int rc = wait_proc(proc_);
    if (too_large_) {
        wipe(mem_);
        return {CryptoStatus::TooLarge, "content exceeds the size limit"};
    }
    CryptoResult r = classify(rc, status_);
    // Refuse anything that was not actually decrypted with integrity protection
    // (e.g. a plain OpenPGP literal packet planted in place of the ciphertext).
    if (r.ok() && status_.find("[GNUPG:] DECRYPTION_OKAY") == std::string::npos) {
        r.status = CryptoStatus::NotEncrypted;
        r.detail = "object is not an encrypted OpenPGP message";
    }
    // Integrity: SEIPDv1 reports GOODMDC; AEAD modes report a non-zero AEAD algo in DECRYPTION_INFO.
    bool aead = false;
    if (size_t i = status_.find("[GNUPG:] DECRYPTION_INFO "); i != std::string::npos) {
        auto f = split(status_.substr(i + 25, status_.find('\n', i) - i - 25), ' ');
        aead = f.size() >= 3 && f[2] != "0";
    }
    if (r.ok() && status_.find("[GNUPG:] GOODMDC") == std::string::npos && !aead) {
        r.status = CryptoStatus::Tampered;
        r.detail = "message has no integrity protection";
    }
    if (!r.ok()) wipe(mem_);
    return r;
}

void Gpg::Decryptor::abort() {
    if (finished_) return;
    kill_proc(proc_);
    if (proc_.in >= 0) { close(proc_.in); proc_.in = -1; }
    join_del(out_thread_);
    join_del(err_thread_);
    wait_proc(proc_);
    wipe(mem_);
    finished_ = true;
}

Gpg::Decryptor::~Decryptor() {
    if (!finished_ && proc_.pid > 0) abort();
    join_del(out_thread_);
    join_del(err_thread_);
    wipe(mem_);
}

}  // namespace s3v
