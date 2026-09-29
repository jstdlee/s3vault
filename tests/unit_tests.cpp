// Unit tests for the pure parts of the core (no network). Run: build/s3vault-tests
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>

#include "config/config.h"
#include "crypto/gpg.h"
#include "preview/preview.h"
#include "secret/passcache.h"
#include "secret/strength.h"
#include "store/sigv4.h"
#include "sync/ignore.h"
#include "sync/planner.h"
#include "util/fs.h"
#include "util/secure.h"
#include "util/sha256.h"
#include "util/strings.h"
#include "util/subprocess.h"
#include "vault/vault.h"

using namespace s3v;

static int g_fail = 0, g_pass = 0;
#define CHECK(cond)                                                             \
    do {                                                                        \
        if (cond) g_pass++;                                                     \
        else { g_fail++; fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); } \
    } while (0)
#define CHECK_EQ(a, b)                                                                                    \
    do {                                                                                                  \
        auto _a = (a); auto _b = (b);                                                                     \
        if (_a == _b) g_pass++;                                                                           \
        else { g_fail++; fprintf(stderr, "FAIL %s:%d  %s == %s\n", __FILE__, __LINE__, #a, #b); }         \
    } while (0)

static void test_hashes() {
    CHECK_EQ(sha256_hex(""), std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK_EQ(sha256_hex("abc"), std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    std::string m(1000000, 'a');
    CHECK_EQ(sha256_hex(m), std::string("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    // RFC 4231 test case 2
    CHECK_EQ(to_hex(hmac_sha256_raw("Jefe", "what do ya want for nothing?")),
             std::string("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
}

static void test_sigv4() {
    // AWS S3 documentation example: GET Object with Range.
    SigV4Request r;
    r.method = "GET";
    r.host = "examplebucket.s3.amazonaws.com";
    r.path = "/test.txt";
    r.headers["range"] = "bytes=0-9";
    r.payload_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    sigv4_sign(r, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", 1369353600);
    CHECK(r.headers["authorization"].find("Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41") !=
          std::string::npos);
    CHECK(r.headers["authorization"].find("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date") != std::string::npos);
    CHECK_EQ(canonical_query({{"prefix", "a b/c"}, {"list-type", "2"}}), std::string("list-type=2&prefix=a%20b%2Fc"));
}

static void test_strings() {
    CHECK_EQ(parse_iso8601("2026-09-29T05:42:55.484Z"), int64_t(1790660575));
    CHECK_EQ(path_ext_lower("a/b/Report.PDF"), std::string("pdf"));
    CHECK_EQ(path_ext_lower(".bashrc"), std::string(""));
    CHECK_EQ(path_dirname("a/b/c.txt"), std::string("a/b"));
    CHECK_EQ(path_basename("a/b/c.txt"), std::string("c.txt"));
    CHECK(utf8_valid("héllo 世界"));
    CHECK(!utf8_valid(std::string("ab\xff", 3)));
    CHECK(!utf8_valid(std::string("a\0b", 3)));
    CHECK(!utf8_valid("\xe4\xb8"));  // truncated
    std::string c = Vault::conflict_name("docs/notes.md", "remote");
    CHECK(starts_with(c, "docs/notes (conflict remote "));
    CHECK(ends_with(c, ").md"));
}

static void test_ignore() {
    IgnoreRules r;
    CHECK(r.ignored(".DS_Store", false));
    CHECK(r.ignored("a/b/.DS_Store", false));
    CHECK(r.ignored("x/.notes.md.s3v-tmp", false));
    CHECK(r.ignored(".s3vault-trash/20260101/a.txt", false));
    CHECK(!r.ignored("notes.md", false));
    r.add_pattern("build/");
    r.add_pattern("*.log");
    r.add_pattern("!keep.log");
    r.add_pattern("/top-only.txt");
    r.add_pattern("docs/**/*.tmp");
    CHECK(r.ignored("build/out.o", false));
    CHECK(r.ignored("src/build/x", false));
    CHECK(!r.ignored("build", false));  // a file named build
    CHECK(r.ignored("a.log", false));
    CHECK(!r.ignored("keep.log", false));
    CHECK(r.ignored("top-only.txt", false));
    CHECK(!r.ignored("sub/top-only.txt", false));
    CHECK(r.ignored("docs/a/b/x.tmp", false));
    CHECK(r.ignored("docs/x.tmp", false));
}

static void test_strength() {
    CHECK(!check_password("short1!", 14).acceptable);
    CHECK(!check_password("aaaaaaaaaaaaaaaaaaaa", 14).acceptable);
    CHECK(!check_password("password12345678!", 14).acceptable);
    CHECK(!check_password("abcdefghijklmnop1", 14).acceptable);
    CHECK(check_password("Tr0ub4dor&3-horse-Staple", 14).acceptable);
    std::string g = generate_password();
    CHECK_EQ(g.size(), size_t(29));
    CHECK(check_password(g, 14).acceptable);
    CHECK(generate_password() != g);
}

static void test_passcache() {
    PassCache p;
    p.configure(PassCache::Mode::Idle, 15);
    CHECK(!p.unlocked());
    p.set("k");
    CHECK(p.unlocked());
    CHECK_EQ(std::string(p.get().view()), std::string("k"));
    p.lock();
    CHECK(p.get().empty());
    p.configure(PassCache::Mode::Ask, 15);
    p.set("k2");
    p.release_if_ask();
    CHECK(!p.unlocked());
}

// ---- planner ----
static PlanInput base_input() {
    PlanInput in;
    in.vault_prefix = "v/";
    in.remote_prefix = "docs";
    in.default_encrypt = true;
    return in;
}
static FileRow row(const std::string& rel, const std::string& etag, const std::string& hash, const std::string& key) {
    FileRow f;
    f.rel = rel;
    f.base_etag = etag;
    f.base_hash = hash;
    f.remote_key = key;
    return f;
}
static const Action* only(const std::vector<Action>& a) { return a.size() == 1 ? &a[0] : nullptr; }

static void test_planner() {
    // unchanged
    {
        PlanInput in = base_input();
        in.local["a"] = {1, 1, 1, "h1"};
        in.remote["a"] = {"v/docs/a.gpg", "e1", 1, 1, true};
        in.base["a"] = row("a", "e1", "h1", "v/docs/a.gpg");
        CHECK(plan_sync(in).empty());
    }
    // local changed → conditional upload to the same key
    {
        PlanInput in = base_input();
        in.local["a"] = {1, 1, 1, "h2"};
        in.remote["a"] = {"v/docs/a.gpg", "e1", 1, 1, true};
        in.base["a"] = row("a", "e1", "h1", "v/docs/a.gpg");
        auto p = plan_sync(in);
        CHECK(only(p) && p[0].kind == ActKind::Upload && p[0].if_match == "e1" && p[0].key == "v/docs/a.gpg");
    }
    // remote changed → download
    {
        PlanInput in = base_input();
        in.local["a"] = {1, 1, 1, "h1"};
        in.remote["a"] = {"v/docs/a.gpg", "e2", 1, 1, true};
        in.base["a"] = row("a", "e1", "h1", "v/docs/a.gpg");
        auto p = plan_sync(in);
        CHECK(only(p) && p[0].kind == ActKind::Download);
    }
    // both changed → compare first
    {
        PlanInput in = base_input();
        in.local["a"] = {1, 1, 1, "h2"};
        in.remote["a"] = {"v/docs/a.gpg", "e2", 1, 1, true};
        in.base["a"] = row("a", "e1", "h1", "v/docs/a.gpg");
        auto p = plan_sync(in);
        CHECK(only(p) && p[0].kind == ActKind::CheckEqual && p[0].conflict_kind == "both-modified");
    }
    // new local file → upload with If-None-Match, encrypted by default
    {
        PlanInput in = base_input();
        in.local["n.txt"] = {1, 1, 1, "h"};
        auto p = plan_sync(in);
        CHECK(only(p) && p[0].kind == ActKind::Upload && p[0].if_none_match && p[0].key == "v/docs/n.txt.gpg");
        in.default_encrypt = false;
        p = plan_sync(in);
        CHECK(only(p) && p[0].key == "v/docs/n.txt");
        in.local.clear();
        in.local["x.gpg"] = {1, 1, 1, "h"};  // *.gpg files are always encrypted (unambiguous suffix)
        p = plan_sync(in);
        CHECK(only(p) && p[0].key == "v/docs/x.gpg.gpg");
    }
    // new remote file → download
    {
        PlanInput in = base_input();
        in.remote["r"] = {"v/docs/r", "e", 1, 1, false};
        auto p = plan_sync(in);
        CHECK(only(p) && p[0].kind == ActKind::Download);
    }
    // both added → compare
    {
        PlanInput in = base_input();
        in.local["r"] = {1, 1, 1, "h"};
        in.remote["r"] = {"v/docs/r", "e", 1, 1, false};
        auto p = plan_sync(in);
        CHECK(only(p) && p[0].kind == ActKind::CheckEqual && p[0].conflict_kind == "both-added");
    }
    // deleted remotely, unchanged locally → delete local; changed locally → conflict
    {
        PlanInput in = base_input();
        in.local["a"] = {1, 1, 1, "h1"};
        in.base["a"] = row("a", "e1", "h1", "v/docs/a.gpg");
        auto p = plan_sync(in);
        CHECK(only(p) && p[0].kind == ActKind::DeleteLocal);
        in.local["a"].hash = "h2";
        p = plan_sync(in);
        CHECK(only(p) && p[0].kind == ActKind::Conflict && p[0].conflict_kind == "remote-deleted");
    }
    // deleted locally, unchanged remotely → delete remote; changed remotely → conflict
    {
        PlanInput in = base_input();
        in.remote["a"] = {"v/docs/a.gpg", "e1", 1, 1, true};
        in.base["a"] = row("a", "e1", "h1", "v/docs/a.gpg");
        auto p = plan_sync(in);
        CHECK(only(p) && p[0].kind == ActKind::DeleteRemote && p[0].if_match == "e1");
        in.remote["a"].etag = "e2";
        p = plan_sync(in);
        CHECK(only(p) && p[0].kind == ActKind::Conflict && p[0].conflict_kind == "local-deleted");
    }
    // gone on both sides → forget
    {
        PlanInput in = base_input();
        in.base["a"] = row("a", "e1", "h1", "v/docs/a.gpg");
        auto p = plan_sync(in);
        CHECK(only(p) && p[0].kind == ActKind::ForgetBase);
    }
    // upload-only: no downloads, no remote deletes; download-only: no uploads, restores local deletions
    {
        PlanInput in = base_input();
        in.direction = "upload-only";
        in.remote["r"] = {"v/docs/r", "e", 1, 1, false};
        in.remote["a"] = {"v/docs/a", "e1", 1, 1, false};
        in.base["a"] = row("a", "e1", "h1", "v/docs/a");
        CHECK(plan_sync(in).empty());
        in.direction = "download-only";
        in.local["n"] = {1, 1, 1, "h"};
        auto p = plan_sync(in);
        CHECK(p.size() == 2 && p[0].kind == ActKind::Download && p[1].kind == ActKind::Download);
    }
    // base row without a synced etag (only a cached hash) is not a base
    {
        PlanInput in = base_input();
        in.local["a"] = {1, 1, 1, "h"};
        in.base["a"] = row("a", "", "", "");
        auto p = plan_sync(in);
        CHECK(only(p) && p[0].kind == ActKind::Upload && p[0].if_none_match);
    }
}

static void test_gpg() {
    Gpg g("auto");
    if (!g.available()) {
        fprintf(stderr, "skip gpg tests (gpg not found)\n");
        return;
    }
    std::string ct, pt;
    CHECK(g.encrypt_string("hello vault", ct, "key-1").ok());
    CHECK(g.decrypt_string(ct, pt, "key-1").ok());
    CHECK_EQ(pt, std::string("hello vault"));
    CryptoResult bad = g.decrypt_string(ct, pt, "key-2");
    CHECK(bad.status == CryptoStatus::BadPassphrase);
    CHECK(pt.empty());
    // Output cap
    std::string big(100000, 'x'), bct;
    CHECK(g.encrypt_string(big, bct, "k").ok());
    CryptoResult tl = g.decrypt_string(bct, pt, "k", 1000);
    CHECK(tl.status == CryptoStatus::TooLarge);
    // A plain OpenPGP literal packet (no encryption) must be refused.
    std::string lit;
    int rc = run_capture({g.exe(), "--batch", "--store", "-o", "-"}, "planted", &lit, nullptr, 1 << 20, 10000, true);
    CHECK(rc == 0 && !lit.empty());
    CryptoResult nr = g.decrypt_string(lit, pt, "k");
    CHECK(nr.status == CryptoStatus::NotEncrypted);
    // Tampering is detected.
    std::string t = ct;
    t[t.size() - 5] ^= 1;
    CryptoResult tr = g.decrypt_string(t, pt, "key-1");
    CHECK(!tr.ok());
    // File round trip with the strong S2K used for key.gpg
    std::string dir = "/tmp/s3vault-test-" + std::to_string(getpid());
    mkdirs(dir);
    write_file_atomic(dir + "/in.txt", "file body", 0600);
    CHECK(g.encrypt_file(dir + "/in.txt", dir + "/out.gpg", "pw", true, false).ok());
    std::string enc;
    read_file(dir + "/out.gpg", enc);
    CHECK(g.decrypt_string(enc, pt, "pw").ok() && pt == "file body");
    remove_tree(dir);
}

static void test_config() {
    Config c;
    c.set("storage.bucket", "b1");
    c.set("sync.concurrency", "3");
    std::string p = "/tmp/s3vault-cfg-" + std::to_string(getpid()) + ".ini";
    CHECK(c.save(p));
    Config d;
    CHECK(d.load(p));
    CHECK_EQ(d.storage.bucket, std::string("b1"));
    CHECK_EQ(d.sync.concurrency, 3);
    unlink(p.c_str());
    StorageConfig s;
    s.provider = "aws";
    s.region = "eu-west-1";
    s.bucket = "bk";
    s.access_key_id = "AK";
    S3Endpoint ep;
    std::string err;
    CHECK(resolve_endpoint(s, "sec", ep, err));
    CHECK_EQ(ep.host, std::string("s3.eu-west-1.amazonaws.com"));
    CHECK(!ep.path_style);
    s.provider = "r2";
    s.region = "auto";
    s.account_id = "acct";
    CHECK(resolve_endpoint(s, "sec", ep, err));
    CHECK_EQ(ep.host, std::string("acct.r2.cloudflarestorage.com"));
    CHECK(ep.path_style);
    s.account_id = "";
    CHECK(!resolve_endpoint(s, "sec", ep, err));
}

int main() {
    test_hashes();
    test_sigv4();
    test_strings();
    test_ignore();
    test_strength();
    test_passcache();
    test_planner();
    test_gpg();
    test_config();
    printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
