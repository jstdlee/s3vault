// libcurl loaded at runtime (libcurl.so.4), so the binary needs no -dev package to build.
#pragma once
#include <curl/curl.h>

namespace s3v {

struct CurlApi {
    CURLcode (*global_init)(long);
    CURL* (*easy_init)();
    CURLcode (*easy_setopt)(CURL*, CURLoption, ...);
    CURLcode (*easy_perform)(CURL*);
    CURLcode (*easy_getinfo)(CURL*, CURLINFO, ...);
    void (*easy_cleanup)(CURL*);
    void (*easy_reset)(CURL*);
    const char* (*easy_strerror)(CURLcode);
    curl_slist* (*slist_append)(curl_slist*, const char*);
    void (*slist_free_all)(curl_slist*);
};

// nullptr if libcurl cannot be loaded; `error` explains why.
const CurlApi* curl_api(const char** error = nullptr);

}  // namespace s3v
