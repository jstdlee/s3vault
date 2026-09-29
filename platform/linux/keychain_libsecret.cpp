// Secrets in the freedesktop Secret Service (GNOME Keyring / KWallet) through libsecret, loaded at runtime.
#include <dlfcn.h>

#include <cstdlib>
#include <ctime>
#include <mutex>
#include <string>
#include <type_traits>

#include "platform.h"
#include "util/secure.h"

namespace s3v::platform {

namespace {

// Minimal libsecret/glib ABI (stable since libsecret 0.18).
struct SecretSchemaAttribute {
    const char* name;
    int type;  // 0 = string
};
struct SecretSchema {
    const char* name;
    int flags;
    SecretSchemaAttribute attributes[32];
    int reserved;
    void* reserved1;
    void* reserved2;
    void* reserved3;
    void* reserved4;
    void* reserved5;
    void* reserved6;
    void* reserved7;
};
struct GError {
    unsigned domain;
    int code;
    char* message;
};

struct Api {
    void* (*hash_new)(unsigned (*)(const void*), int (*)(const void*, const void*));
    int (*hash_insert)(void*, void*, void*);
    void (*hash_unref)(void*);
    unsigned (*str_hash)(const void*);
    int (*str_equal)(const void*, const void*);
    void (*error_free)(GError*);
    int (*storev)(const SecretSchema*, void*, const char*, const char*, const char*, void*, GError**);
    char* (*lookupv)(const SecretSchema*, void*, void*, GError**);
    int (*clearv)(const SecretSchema*, void*, void*, GError**);
    void (*password_free)(char*);
};

const Api* api() {
    static Api a;
    static const Api* ok = nullptr;
    static std::once_flag once;
    std::call_once(once, [] {
        void* s = dlopen("libsecret-1.so.0", RTLD_NOW | RTLD_LOCAL);
        void* g = dlopen("libglib-2.0.so.0", RTLD_NOW | RTLD_LOCAL);
        if (!s || !g) return;
        bool all = true;
        auto sym = [&](void* lib, auto& fn, const char* n) {
            fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(dlsym(lib, n));
            if (!fn) all = false;
        };
        sym(g, a.hash_new, "g_hash_table_new");
        sym(g, a.hash_insert, "g_hash_table_insert");
        sym(g, a.hash_unref, "g_hash_table_unref");
        sym(g, a.str_hash, "g_str_hash");
        sym(g, a.str_equal, "g_str_equal");
        sym(g, a.error_free, "g_error_free");
        sym(s, a.storev, "secret_password_storev_sync");
        sym(s, a.lookupv, "secret_password_lookupv_sync");
        sym(s, a.clearv, "secret_password_clearv_sync");
        sym(s, a.password_free, "secret_password_free");
        if (all) ok = &a;
    });
    return ok;
}

const SecretSchema* schema() {
    static SecretSchema s = [] {
        SecretSchema x{};
        x.name = "org.s3vault.Secret";
        x.flags = 0;
        x.attributes[0] = {"account", 0};
        x.attributes[1] = {nullptr, 0};
        return x;
    }();
    return &s;
}

void* attrs(const Api* a, const std::string& account) {
    void* h = a->hash_new(a->str_hash, a->str_equal);
    a->hash_insert(h, const_cast<char*>("account"), const_cast<char*>(account.c_str()));
    return h;
}

}  // namespace

void keychain_preload() {
    if (!api() || !getenv("DBUS_SESSION_BUS_ADDRESS")) return;
    SecureString unused;
    keychain_load("s3vault-preload", unused);  // starts GDBus and initialises libgcrypt now, not on a worker thread
}

bool keychain_available() {
    const Api* a = api();
    if (!a || !getenv("DBUS_SESSION_BUS_ADDRESS")) return false;
    return true;
}

bool keychain_store(const std::string& account, std::string_view secret, int64_t expires_unix) {
    const Api* a = api();
    if (!a) return false;
    // Stored as "<expires>:<secret>" so expiry is enforced on read.
    std::string value = std::to_string(expires_unix) + ":" + std::string(secret);
    void* h = attrs(a, account);
    GError* err = nullptr;
    std::string label = "s3vault: " + account;
    int ok = a->storev(schema(), h, nullptr /* default collection */, label.c_str(), value.c_str(), nullptr, &err);
    a->hash_unref(h);
    wipe(value);
    if (err) a->error_free(err);
    return ok != 0;
}

bool keychain_load(const std::string& account, SecureString& out) {
    const Api* a = api();
    if (!a) return false;
    void* h = attrs(a, account);
    GError* err = nullptr;
    char* v = a->lookupv(schema(), h, nullptr, &err);
    a->hash_unref(h);
    if (err) a->error_free(err);
    if (!v) return false;
    std::string_view sv(v);
    size_t c = sv.find(':');
    bool ok = false;
    if (c != std::string_view::npos) {
        int64_t exp = atoll(std::string(sv.substr(0, c)).c_str());
        if (exp == 0 || exp > int64_t(time(nullptr))) {
            out.assign(sv.substr(c + 1));
            ok = true;
        }
    }
    a->password_free(v);
    if (!ok) keychain_erase(account);
    return ok;
}

bool keychain_erase(const std::string& account) {
    const Api* a = api();
    if (!a) return false;
    void* h = attrs(a, account);
    GError* err = nullptr;
    int ok = a->clearv(schema(), h, nullptr, &err);
    a->hash_unref(h);
    if (err) a->error_free(err);
    return ok != 0;
}

}  // namespace s3v::platform
