// AWS Signature Version 4 for S3-compatible services.
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace s3v {

struct SigV4Request {
    std::string method;                          // GET, PUT, …
    std::string host;                            // "bucket.s3.eu-west-1.amazonaws.com"
    std::string path;                            // already URI-encoded, e.g. "/bucket/a%20b.txt"
    std::map<std::string, std::string> query;    // raw (unencoded) name → value
    std::map<std::string, std::string> headers;  // lower-case names; host/x-amz-date/x-amz-content-sha256 added
    std::string payload_sha256;                  // hex, or "UNSIGNED-PAYLOAD"
};

// Adds x-amz-date, x-amz-content-sha256 and authorization to req.headers.
void sigv4_sign(SigV4Request& req, const std::string& access_key, const std::string& secret_key,
                const std::string& region, int64_t unix_time, const std::string& service = "s3");

// "a=1&b=x%2Fy" (sorted, encoded) — also used to build the URL.
std::string canonical_query(const std::map<std::string, std::string>& q);

}  // namespace s3v
