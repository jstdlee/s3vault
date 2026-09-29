#include "store/curl_dl.h"

#include <dlfcn.h>

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
        void* h = nullptr;
        for (const char* name : {"libcurl.so.4", "libcurl-gnutls.so.4", "libcurl.so"})
            if ((h = dlopen(name, RTLD_NOW | RTLD_LOCAL))) break;
        if (!h) { err = "libcurl.so.4 not found (install libcurl4)"; return; }
        bool all = true;
        auto sym = [&](auto& fn, const char* n) {
            fn = reinterpret_cast<std::remove_reference_t<decltype(fn)>>(dlsym(h, n));
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
        api.global_init(CURL_GLOBAL_DEFAULT);
        ok = &api;
    });
    if (error) *error = err;
    return ok;
}

}  // namespace s3v
