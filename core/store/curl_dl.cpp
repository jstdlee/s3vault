#include "store/curl_dl.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <initializer_list>
#include <mutex>
#include <type_traits>

namespace s3v {

const CurlApi* curl_api(const char** error) {
    static CurlApi api;
    static const CurlApi* ok = nullptr;
    static const char* err = nullptr;
    static std::once_flag once;
    std::call_once(once, [] {
#ifdef _WIN32
        // Shipped next to the executable (LoadLibrary searches the application folder first).
        HMODULE h = nullptr;
        for (const wchar_t* name : {L"libcurl-4.dll", L"libcurl-x64.dll", L"libcurl.dll"})
            if ((h = LoadLibraryW(name))) break;
        if (!h) { err = "libcurl-4.dll not found (it ships next to s3vault.exe)"; return; }
        auto lookup = [h](const char* n) { return reinterpret_cast<void*>(GetProcAddress(h, n)); };
#else
        void* h = nullptr;
        for (const char* name : {"libcurl.so.4", "libcurl-gnutls.so.4", "libcurl.so"})
            if ((h = dlopen(name, RTLD_NOW | RTLD_LOCAL))) break;
        if (!h) { err = "libcurl.so.4 not found (install libcurl4)"; return; }
        auto lookup = [h](const char* n) { return dlsym(h, n); };
#endif
        bool all = true;
        auto sym = [&](auto& fn, const char* n) {
            fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(lookup(n));
            if (!fn) all = false;
        };
        sym(api.global_init, "curl_global_init");
        sym(api.easy_init, "curl_easy_init");
        sym(api.easy_setopt, "curl_easy_setopt");
        sym(api.easy_perform, "curl_easy_perform");
        sym(api.easy_getinfo, "curl_easy_getinfo");
        sym(api.easy_cleanup, "curl_easy_cleanup");
        sym(api.easy_reset, "curl_easy_reset");
        sym(api.easy_strerror, "curl_easy_strerror");
        sym(api.slist_append, "curl_slist_append");
        sym(api.slist_free_all, "curl_slist_free_all");
        if (!all) { err = "libcurl is missing symbols"; return; }
#ifdef _WIN32
        // Prefer Schannel (Windows certificate store) when this libcurl has several TLS backends.
        using SslSet = int (*)(int, const char*, const void***);
        if (auto sslset = reinterpret_cast<SslSet>(lookup("curl_global_sslset"))) sslset(8 /* CURLSSLBACKEND_SCHANNEL */, nullptr, nullptr);
#endif
        api.global_init(CURL_GLOBAL_DEFAULT);
        ok = &api;
    });
    if (error) *error = err;
    return ok;
}

}  // namespace s3v
