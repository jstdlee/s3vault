#include "store/sigv4.h"

#include "util/sha256.h"
#include "util/strings.h"

namespace s3v {

std::string canonical_query(const std::map<std::string, std::string>& q) {
    std::string r;
    for (auto& [k, v] : q) {
        if (!r.empty()) r += '&';
        r += uri_encode(k, true) + "=" + uri_encode(v, true);
    }
    return r;
}

void sigv4_sign(SigV4Request& req, const std::string& access_key, const std::string& secret_key,
                const std::string& region, int64_t unix_time, const std::string& service) {
    std::string amz_date = format_utc_compact(unix_time);  // 20260929T054255Z
    std::string date = amz_date.substr(0, 8);
    req.headers["host"] = req.host;
    req.headers["x-amz-date"] = amz_date;
    req.headers["x-amz-content-sha256"] = req.payload_sha256;

    std::string canon_headers, signed_headers;
    for (auto& [k, v] : req.headers) {
        if (k == "authorization") continue;
        canon_headers += k + ":" + trim(v) + "\n";
        if (!signed_headers.empty()) signed_headers += ';';
        signed_headers += k;
    }
    std::string creq = req.method + "\n" + req.path + "\n" + canonical_query(req.query) + "\n" + canon_headers +
                       "\n" + signed_headers + "\n" + req.payload_sha256;
    std::string scope = date + "/" + region + "/" + service + "/aws4_request";
    std::string sts = "AWS4-HMAC-SHA256\n" + amz_date + "\n" + scope + "\n" + sha256_hex(creq);
    std::string k = hmac_sha256_raw("AWS4" + secret_key, date);
    k = hmac_sha256_raw(k, region);
    k = hmac_sha256_raw(k, service);
    k = hmac_sha256_raw(k, "aws4_request");
    std::string sig = to_hex(hmac_sha256_raw(k, sts));
    req.headers["authorization"] = "AWS4-HMAC-SHA256 Credential=" + access_key + "/" + scope +
                                   ", SignedHeaders=" + signed_headers + ", Signature=" + sig;
}

}  // namespace s3v
