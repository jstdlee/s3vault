#include "store/s3_client.h"

#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <thread>

#include "config/config.h"
#include "pugixml.hpp"
#include "store/curl_dl.h"
#include "store/sigv4.h"
#include "util/sha256.h"
#include "util/strings.h"

namespace s3v {

static const char* kEmptySha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

std::string S3Result::describe() const {
    std::string s = http ? "HTTP " + std::to_string(http) : "network error";
    if (!code.empty()) s += " " + code;
    if (!message.empty()) s += ": " + message;
    return s;
}

bool resolve_endpoint(const StorageConfig& c, const std::string& secret, S3Endpoint& out, std::string& error) {
    out = S3Endpoint{};
    std::string ep = c.endpoint == "auto" ? "" : c.endpoint;
    std::string region = c.region == "auto" ? "" : c.region;
    bool path_style = true;
    const std::string& p = c.provider;
    if (p == "r2") {
        if (ep.empty()) {
            if (c.account_id.empty()) { error = "storage.account_id is required for R2"; return false; }
            ep = "https://" + c.account_id + ".r2.cloudflarestorage.com";
        }
        if (region.empty()) region = "auto";
    } else if (p == "aws") {
        if (region.empty()) region = "us-east-1";
        if (ep.empty()) ep = "https://s3." + region + ".amazonaws.com";
        path_style = false;
    } else if (p == "b2") {
        if (region.empty()) { error = "storage.region is required for B2 (e.g. us-west-004)"; return false; }
        if (ep.empty()) ep = "https://s3." + region + ".backblazeb2.com";
        path_style = false;
    } else if (p == "wasabi") {
        if (region.empty()) region = "us-east-1";
        if (ep.empty()) ep = "https://s3." + region + ".wasabisys.com";
        path_style = false;
    } else {  // minio / custom
        if (ep.empty()) { error = "storage.endpoint is required for provider " + p; return false; }
        if (region.empty()) region = "us-east-1";
    }
    if (c.addressing == "path") path_style = true;
    if (c.addressing == "virtual") path_style = false;
    if (c.bucket.empty()) { error = "storage.bucket is not set"; return false; }
    if (c.access_key_id.empty()) { error = "storage.access_key_id is not set"; return false; }
    if (secret.empty()) { error = "S3 secret key is not set"; return false; }
    size_t sep = ep.find("://");
    out.scheme = sep == std::string::npos ? "https" : ep.substr(0, sep);
    out.host = sep == std::string::npos ? ep : ep.substr(sep + 3);
    while (!out.host.empty() && out.host.back() == '/') out.host.pop_back();
    out.region = region;
    out.bucket = c.bucket;
    out.path_style = path_style;
    out.access_key = c.access_key_id;
    out.secret_key.assign(secret);
    return true;
}

struct S3Client::Req {
    std::string method = "GET";
    std::string key;                             // object key ("" = bucket)
    std::map<std::string, std::string> query;
    std::map<std::string, std::string> headers;  // lower-case
    // Body source: in-memory or file range.
    const std::string* body = nullptr;
    FILE* file = nullptr;
    uint64_t file_len = 0;
    std::string payload_sha = kEmptySha;
    // Response
    std::function<bool(const char*, size_t)> sink;  // streaming body
    std::string resp_body;                          // when no sink (capped)
    std::map<std::string, std::string> resp_headers;
    size_t delivered = 0;
    bool aborted = false;
    std::function<void(uint64_t)> on_upload;
    std::atomic<bool>* cancel = nullptr;
    bool no_cancel = false;  // cleanup requests (abort multipart) must still go out after a cancel
};

namespace {

struct Upload {
    const std::string* body;
    FILE* file;
    uint64_t off = 0, len = 0;
    const std::function<void(uint64_t)>* progress;
};

size_t read_cb(char* buf, size_t sz, size_t n, void* ud) {
    auto* u = static_cast<Upload*>(ud);
    size_t want = std::min<uint64_t>(sz * n, u->len - u->off);
    if (!want) return 0;
    size_t got;
    if (u->body) {
        memcpy(buf, u->body->data() + u->off, want);
        got = want;
    } else {
        got = fread(buf, 1, want, u->file);
        if (got == 0) return CURL_READFUNC_ABORT;
    }
    u->off += got;
    if (u->progress && *u->progress) (*u->progress)(u->off);
    return got;
}

}  // namespace

static size_t write_cb(char* p, size_t sz, size_t n, void* ud) {
    auto* r = static_cast<S3Client::Req*>(ud);
    size_t len = sz * n;
    if (r->sink && r->resp_headers.count(":ok")) {
        if (!r->sink(p, len)) { r->aborted = true; return 0; }
        r->delivered += len;
        return len;
    }
    if (r->resp_body.size() < (64u << 20)) r->resp_body.append(p, len);
    return len;
}

static int progress_cb(void* ud, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    auto* r = static_cast<S3Client::Req*>(ud);
    return r->cancel && r->cancel->load() ? 1 : 0;  // non-zero aborts the transfer
}

static size_t header_cb(char* p, size_t sz, size_t n, void* ud) {
    auto* r = static_cast<S3Client::Req*>(ud);
    std::string line(p, sz * n);
    if (starts_with(line, "HTTP/")) {
        r->resp_headers.clear();
        int code = 0;
        size_t sp = line.find(' ');
        if (sp != std::string::npos) code = atoi(line.c_str() + sp + 1);
        if (code >= 200 && code < 300) r->resp_headers[":ok"] = "1";
        return sz * n;
    }
    size_t c = line.find(':');
    if (c != std::string::npos) r->resp_headers[to_lower(trim(line.substr(0, c)))] = trim(line.substr(c + 1));
    return sz * n;
}

static std::string unquote(std::string s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') s = s.substr(1, s.size() - 2);
    return s;
}

static void parse_error(const std::string& body, S3Result& res) {
    pugi::xml_document doc;
    if (!doc.load_buffer(body.data(), body.size())) return;
    auto e = doc.child("Error");
    if (!e) return;
    res.code = e.child_value("Code");
    res.message = e.child_value("Message");
}

S3Result S3Client::perform(Req& r) {
    S3Result res;
    if (!r.no_cancel) r.cancel = &cancel;
    const char* why = nullptr;
    const CurlApi* c = curl_api(&why);
    if (!c) { res.code = why; return res; }
    thread_local CURL* h = nullptr;
    if (!h) h = c->easy_init();
    if (!h) { res.code = "curl_easy_init failed"; return res; }

    std::string host = ep_.path_style ? ep_.host : ep_.bucket + "." + ep_.host;
    std::string path = "/";
    if (ep_.path_style) path += uri_encode(ep_.bucket, true) + (r.key.empty() ? "" : "/");
    path += uri_encode(r.key, false);
    std::string qs = canonical_query(r.query);
    std::string url = ep_.scheme + "://" + host + path + (qs.empty() ? "" : "?" + qs);

    for (int attempt = 0;; attempt++) {
        SigV4Request sr;
        sr.method = r.method;
        sr.host = host;
        sr.path = path;
        sr.query = r.query;
        sr.headers = r.headers;
        sr.payload_sha256 = r.payload_sha;
        sigv4_sign(sr, ep_.access_key, std::string(ep_.secret_key.view()), ep_.region, int64_t(time(nullptr)));

        c->easy_reset(h);
        curl_slist* hl = nullptr;
        for (auto& [k, v] : sr.headers) {
            if (k == "host") continue;
            hl = c->slist_append(hl, (k + ": " + v).c_str());
        }
        hl = c->slist_append(hl, "Expect:");
        c->easy_setopt(h, CURLOPT_URL, url.c_str());
        c->easy_setopt(h, CURLOPT_HTTPHEADER, hl);
        c->easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
        c->easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 20L);
        c->easy_setopt(h, CURLOPT_LOW_SPEED_LIMIT, 1L);
        c->easy_setopt(h, CURLOPT_LOW_SPEED_TIME, 60L);
        c->easy_setopt(h, CURLOPT_WRITEFUNCTION, write_cb);
        c->easy_setopt(h, CURLOPT_WRITEDATA, &r);
        c->easy_setopt(h, CURLOPT_HEADERFUNCTION, header_cb);
        c->easy_setopt(h, CURLOPT_HEADERDATA, &r);
        c->easy_setopt(h, CURLOPT_NOPROGRESS, 0L);
        c->easy_setopt(h, CURLOPT_XFERINFOFUNCTION, progress_cb);
        c->easy_setopt(h, CURLOPT_XFERINFODATA, &r);
        if (max_bytes_per_sec > 0) {
            c->easy_setopt(h, CURLOPT_MAX_SEND_SPEED_LARGE, curl_off_t(max_bytes_per_sec));
            c->easy_setopt(h, CURLOPT_MAX_RECV_SPEED_LARGE, curl_off_t(max_bytes_per_sec));
        }
        Upload up{r.body, r.file, 0, r.body ? r.body->size() : r.file_len, &r.on_upload};
        long file_start = r.file ? ftell(r.file) : 0;
        if (r.method == "PUT") {
            c->easy_setopt(h, CURLOPT_UPLOAD, 1L);
            c->easy_setopt(h, CURLOPT_READFUNCTION, read_cb);
            c->easy_setopt(h, CURLOPT_READDATA, &up);
            c->easy_setopt(h, CURLOPT_INFILESIZE_LARGE, curl_off_t(up.len));
        } else if (r.method == "POST") {
            c->easy_setopt(h, CURLOPT_POST, 1L);
            c->easy_setopt(h, CURLOPT_READFUNCTION, read_cb);
            c->easy_setopt(h, CURLOPT_READDATA, &up);
            c->easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE, curl_off_t(up.len));
        } else if (r.method == "HEAD") {
            c->easy_setopt(h, CURLOPT_NOBODY, 1L);
        } else if (r.method != "GET") {
            c->easy_setopt(h, CURLOPT_CUSTOMREQUEST, r.method.c_str());
        }
        r.resp_body.clear();
        r.resp_headers.clear();
        r.aborted = false;
        CURLcode cc = c->easy_perform(h);
        c->slist_free_all(hl);
        long http = 0;
        c->easy_getinfo(h, CURLINFO_RESPONSE_CODE, &http);

        res = S3Result{};
        res.http = cc == CURLE_OK ? int(http) : 0;
        if (r.aborted) {
            res.http = 0;
            res.code = "Aborted";
            return res;
        }
        if (r.cancel && *r.cancel) {
            res.http = 0;
            res.code = "Cancelled";
            return res;
        }
        if (cc != CURLE_OK) res.code = c->easy_strerror(cc);
        else if (!res.ok()) parse_error(r.resp_body, res);
        if (auto it = r.resp_headers.find("etag"); it != r.resp_headers.end()) res.etag = unquote(it->second);

        bool transient = res.http == 0 || res.http == 429 || res.http >= 500;
        // A streamed GET can only be retried if nothing reached the sink yet.
        if (!transient || attempt >= 4 || r.delivered > 0) return res;
        if (r.file) fseek(r.file, file_start, SEEK_SET);
        std::this_thread::sleep_for(std::chrono::milliseconds(500 << attempt));
    }
}

S3Result S3Client::list_all(const std::string& prefix, std::vector<ObjectInfo>& out) {
    std::string token;
    for (;;) {
        Req r;
        r.query["list-type"] = "2";
        r.query["max-keys"] = "1000";
        if (!prefix.empty()) r.query["prefix"] = prefix;
        if (!token.empty()) r.query["continuation-token"] = token;
        S3Result res = perform(r);
        if (!res.ok()) return res;
        pugi::xml_document doc;
        if (!doc.load_buffer(r.resp_body.data(), r.resp_body.size())) {
            res.http = 0;
            res.code = "bad ListObjectsV2 XML";
            return res;
        }
        auto root = doc.child("ListBucketResult");
        for (auto ct : root.children("Contents")) {
            ObjectInfo o;
            o.key = ct.child_value("Key");
            o.size = strtoull(ct.child_value("Size"), nullptr, 10);
            o.etag = unquote(ct.child_value("ETag"));
            o.mtime = parse_iso8601(ct.child_value("LastModified"));
            out.push_back(std::move(o));
        }
        std::string trunc = root.child_value("IsTruncated");
        token = root.child_value("NextContinuationToken");
        if (trunc != "true" || token.empty()) return res;
    }
}

S3Result S3Client::head(const std::string& key, ObjectInfo* info) {
    Req r;
    r.method = "HEAD";
    r.key = key;
    S3Result res = perform(r);
    if (res.ok() && info) {
        info->key = key;
        info->etag = res.etag;
        info->size = strtoull(r.resp_headers["content-length"].c_str(), nullptr, 10);
        struct tm tmv {};
        if (strptime(r.resp_headers["last-modified"].c_str(), "%a, %d %b %Y %H:%M:%S", &tmv)) info->mtime = timegm(&tmv);
    }
    return res;
}

S3Result S3Client::get(const std::string& key, const std::function<bool(const char*, size_t)>& sink,
                       std::string* etag_out) {
    Req r;
    r.key = key;
    r.sink = sink;
    S3Result res = perform(r);
    if (etag_out) *etag_out = res.etag;
    return res;
}

S3Result S3Client::get_string(const std::string& key, std::string& out, size_t max) {
    out.clear();
    S3Result res = get(key, [&](const char* p, size_t n) {
        if (out.size() + n > max) return false;
        out.append(p, n);
        return true;
    });
    return res;
}

static void apply_conditions(std::map<std::string, std::string>& h, const Conditions& c) {
    if (!c.if_match.empty()) h["if-match"] = "\"" + c.if_match + "\"";
    if (c.if_none_match) h["if-none-match"] = "*";
}

S3Result S3Client::put_string(const std::string& key, const std::string& data, const Conditions& c) {
    Req r;
    r.method = "PUT";
    r.key = key;
    r.body = &data;
    r.payload_sha = sha256_hex(data);
    r.headers["content-type"] = "application/octet-stream";
    apply_conditions(r.headers, c);
    return perform(r);
}

S3Result S3Client::put_file(const std::string& key, const std::string& path, const Conditions& c,
                            const std::function<void(uint64_t, uint64_t)>& progress) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        S3Result res;
        res.code = "cannot open " + path;
        return res;
    }
    fseek(f, 0, SEEK_END);
    uint64_t size = uint64_t(ftell(f));
    if (size > multipart_threshold) {
        fclose(f);
        return put_multipart(key, path, size, c, progress);
    }
    // Hash first so the signature covers the payload (the server verifies it).
    fseek(f, 0, SEEK_SET);
    Sha256 hs;
    char buf[1 << 16];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) hs.update(buf, n);
    fseek(f, 0, SEEK_SET);
    Req r;
    r.method = "PUT";
    r.key = key;
    r.file = f;
    r.file_len = size;
    r.payload_sha = hs.hex();
    r.headers["content-type"] = "application/octet-stream";
    if (progress) r.on_upload = [&](uint64_t done) { progress(done, size); };
    apply_conditions(r.headers, c);
    S3Result res = perform(r);
    fclose(f);
    return res;
}

S3Result S3Client::put_multipart(const std::string& key, const std::string& path, uint64_t size, const Conditions& c,
                                 const std::function<void(uint64_t, uint64_t)>& progress) {
    // Equal-size parts (R2 requires it), ≤ 9000 parts.
    uint64_t part = 16ull << 20;
    while (size / part >= 9000) part *= 2;

    Req init;
    init.method = "POST";
    init.key = key;
    init.query["uploads"] = "";
    std::string empty;
    init.body = &empty;
    init.headers["content-type"] = "application/octet-stream";
    S3Result res = perform(init);
    if (!res.ok()) return res;
    pugi::xml_document d;
    d.load_buffer(init.resp_body.data(), init.resp_body.size());
    std::string upload_id = d.child("InitiateMultipartUploadResult").child_value("UploadId");
    if (upload_id.empty()) {
        res.http = 0;
        res.code = "no UploadId";
        return res;
    }
    auto abort = [&] {
        Req a;
        a.no_cancel = true;
        a.method = "DELETE";
        a.key = key;
        a.query["uploadId"] = upload_id;
        perform(a);
    };

    FILE* f = fopen(path.c_str(), "rb");
    if (!f) { abort(); res.http = 0; res.code = "cannot open " + path; return res; }
    std::vector<std::string> etags;
    std::string chunk;
    uint64_t done = 0;
    for (int num = 1; done < size; num++) {
        chunk.resize(size_t(std::min(part, size - done)));
        if (fread(chunk.data(), 1, chunk.size(), f) != chunk.size()) {
            fclose(f); abort(); res.http = 0; res.code = "read error"; return res;
        }
        Req pr;
        pr.method = "PUT";
        pr.key = key;
        pr.query["partNumber"] = std::to_string(num);
        pr.query["uploadId"] = upload_id;
        pr.body = &chunk;
        pr.payload_sha = sha256_hex(chunk);
        uint64_t base = done;
        if (progress) pr.on_upload = [&, base](uint64_t d2) { progress(base + d2, size); };
        S3Result pres = perform(pr);
        if (!pres.ok()) { fclose(f); abort(); return pres; }
        etags.push_back(pres.etag);
        done += chunk.size();
    }
    fclose(f);

    std::string xml = "<CompleteMultipartUpload>";
    for (size_t i = 0; i < etags.size(); i++)
        xml += "<Part><PartNumber>" + std::to_string(i + 1) + "</PartNumber><ETag>\"" + etags[i] + "\"</ETag></Part>";
    xml += "</CompleteMultipartUpload>";
    Req cr;
    cr.method = "POST";
    cr.key = key;
    cr.query["uploadId"] = upload_id;
    cr.body = &xml;
    cr.payload_sha = sha256_hex(xml);
    cr.headers["content-type"] = "application/xml";
    apply_conditions(cr.headers, c);
    res = perform(cr);
    // CompleteMultipartUpload can return 200 with an <Error> body.
    if (res.ok()) {
        S3Result e;
        parse_error(cr.resp_body, e);
        if (!e.code.empty()) {
            res.http = e.code == "PreconditionFailed" ? 412 : 500;
            res.code = e.code;
            res.message = e.message;
        } else {
            pugi::xml_document cd;
            cd.load_buffer(cr.resp_body.data(), cr.resp_body.size());
            std::string et = unquote(cd.child("CompleteMultipartUploadResult").child_value("ETag"));
            if (!et.empty()) res.etag = et;
        }
    }
    if (!res.ok()) abort();
    return res;
}

S3Result S3Client::copy(const std::string& src_key, const std::string& dst_key) {
    Req r;
    r.method = "PUT";
    r.key = dst_key;
    std::string empty;
    r.body = &empty;
    r.headers["x-amz-copy-source"] = "/" + uri_encode(ep_.bucket, true) + "/" + uri_encode(src_key, false);
    S3Result res = perform(r);
    if (res.ok()) {
        pugi::xml_document d;
        if (d.load_buffer(r.resp_body.data(), r.resp_body.size())) {
            if (auto e = d.child("Error")) {
                res.http = 500;
                res.code = e.child_value("Code");
                res.message = e.child_value("Message");
            } else {
                res.etag = unquote(d.child("CopyObjectResult").child_value("ETag"));
            }
        }
    }
    return res;
}

S3Result S3Client::del(const std::string& key) {
    Req r;
    r.method = "DELETE";
    r.key = key;
    return perform(r);
}

}  // namespace s3v
