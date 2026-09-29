// Test-only helper for the R2 integration script: raw object access under a vault prefix.
#include <cstdio>
#include <string>
#include <vector>

#include "config/config.h"
#include "index/db.h"
#include "util/fs.h"
#include "util/strings.h"
#include "vault/vault.h"

using namespace s3v;

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: it-helper wipe | put-raw <vault-rel-key> <file> | head <vault-rel-key>\n");
        return 2;
    }
    Config cfg;
    cfg.load(config_path());
    Db db;
    db.open(data_dir() + "/index.db");
    Vault v(cfg, db);
    std::string err;
    if (!v.connect(err)) { fprintf(stderr, "%s\n", err.c_str()); return 1; }
    std::string cmd = argv[1];
    if (cmd == "wipe") {
        // Only ever under the test prefix.
        if (v.prefix().find("s3vault-it/") != 0) { fprintf(stderr, "refusing: prefix is not s3vault-it/\n"); return 1; }
        std::vector<ObjectInfo> objs;
        S3Result r = v.s3().list_all(v.prefix(), objs);
        if (!r.ok()) { fprintf(stderr, "%s\n", r.describe().c_str()); return 1; }
        for (auto& o : objs) v.s3().del(o.key);
        printf("deleted %zu objects\n", objs.size());
        return 0;
    }
    if (cmd == "put-raw" && argc >= 4) {
        std::string data;
        read_file(argv[3], data);
        S3Result r = v.s3().put_string(v.prefix() + argv[2], data);
        return r.ok() ? 0 : 1;
    }
    if (cmd == "head" && argc >= 3) {
        ObjectInfo oi;
        S3Result r = v.s3().head(v.prefix() + argv[2], &oi);
        if (!r.ok()) { printf("missing\n"); return 1; }
        printf("%llu %s\n", static_cast<unsigned long long>(oi.size), oi.etag.c_str());
        return 0;
    }
    return 2;
}
