// Minimal S3 API client: enough for s3vault (list/head/get/put/copy/delete/multipart, conditional writes).
#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "util/secure.h"

namespace s3v {

struct StorageConfig;

struct S3Endpoint {
    std::string scheme = "https";
    std::string host;  // endpoint host[:port], without bucket
    std::string region;
    std::string bucket;
    bool path_style = true;
    std::string access_key;
    SecureString secret_key;
};

// Fills endpoint/region/addressing from the provider profile. `error` set when something is missing.
bool resolve_endpoint(const StorageConfig& cfg, const std::string& secret, S3Endpoint& out, std::string& error);

struct ObjectInfo {
    std::string key;
    uint64_t size = 0;
    std::string etag;  // without quotes
    int64_t mtime = 0;  // LastModified, unix seconds
};

struct S3Result {
    int http = 0;           // 0 = transport error
    std::string code;       // S3 error code ("PreconditionFailed", "NoSuchKey"…) or curl error text
    std::string message;
    std::string etag;       // for PUT/COPY/complete
    bool ok() const { return http >= 200 && http < 300; }
    bool precondition_failed() const { return http == 412; }
    bool not_found() const { return http == 404; }
    std::string describe() const;
};

struct Conditions {
    std::string if_match;       // ETag (no quotes)
    bool if_none_match = false;  // If-None-Match: *
};

class S3Client {
public:
    explicit S3Client(S3Endpoint ep) : ep_(std::move(ep)) {}

    // Every object under prefix (paginated internally).
    S3Result list_all(const std::string& prefix, std::vector<ObjectInfo>& out);
    S3Result head(const std::string& key, ObjectInfo* info = nullptr);
    // Streams the body to sink; sink returns false to abort (result.code = "Aborted").
    S3Result get(const std::string& key, const std::function<bool(const char*, size_t)>& sink,
                 std::string* etag_out = nullptr);
    S3Result get_string(const std::string& key, std::string& out, size_t max = 64 << 20);
    S3Result put_string(const std::string& key, const std::string& data, const Conditions& c = {});
    // Uses multipart above `multipart_threshold`.
    S3Result put_file(const std::string& key, const std::string& path, const Conditions& c = {},
                      const std::function<void(uint64_t, uint64_t)>& progress = {});
    S3Result copy(const std::string& src_key, const std::string& dst_key);
    S3Result del(const std::string& key);

    uint64_t multipart_threshold = 64ull << 20;
    int64_t max_bytes_per_sec = 0;  // 0 = unlimited (per transfer)
    const S3Endpoint& endpoint() const { return ep_; }

    struct Req;  // internal request state (public for the curl callbacks)

private:
    S3Result perform(Req& r);
    S3Result put_multipart(const std::string& key, const std::string& path, uint64_t size, const Conditions& c,
                           const std::function<void(uint64_t, uint64_t)>& progress);
    S3Endpoint ep_;
};

}  // namespace s3v
