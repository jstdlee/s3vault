#include "index/db.h"

#include <ctime>

#include "sqlite3.h"
#include "util/fs.h"
#include "util/strings.h"

namespace s3v {

namespace {

struct Stmt {
    sqlite3_stmt* s = nullptr;
    Stmt(sqlite3* db, const char* sql) { sqlite3_prepare_v2(db, sql, -1, &s, nullptr); }
    ~Stmt() { sqlite3_finalize(s); }
    Stmt& bind(int i, const std::string& v) { sqlite3_bind_text(s, i, v.c_str(), int(v.size()), SQLITE_TRANSIENT); return *this; }
    Stmt& bind(int i, int64_t v) { sqlite3_bind_int64(s, i, v); return *this; }
    bool step() { return sqlite3_step(s) == SQLITE_ROW; }
    bool run() { int rc = sqlite3_step(s); return rc == SQLITE_DONE || rc == SQLITE_ROW; }
    std::string str(int c) { auto* t = sqlite3_column_text(s, c); return t ? reinterpret_cast<const char*>(t) : ""; }
    int64_t i64(int c) { return sqlite3_column_int64(s, c); }
};

const char* kSchema = R"(
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS roots(
  id INTEGER PRIMARY KEY, local_path TEXT UNIQUE NOT NULL, remote_prefix TEXT NOT NULL,
  direction TEXT NOT NULL DEFAULT 'two-way', encrypt INTEGER NOT NULL DEFAULT 1, paused INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS files(
  root_id INTEGER NOT NULL REFERENCES roots(id) ON DELETE CASCADE, rel TEXT NOT NULL,
  remote_key TEXT, base_etag TEXT, base_hash TEXT,
  l_size INTEGER, l_mtime INTEGER, l_inode INTEGER, l_hash TEXT,
  PRIMARY KEY(root_id, rel));
CREATE TABLE IF NOT EXISTS conflicts(
  id INTEGER PRIMARY KEY, root_id INTEGER NOT NULL REFERENCES roots(id) ON DELETE CASCADE, rel TEXT NOT NULL,
  kind TEXT, local_exists INTEGER, local_size INTEGER, local_mtime INTEGER, local_hash TEXT,
  remote_exists INTEGER, remote_key TEXT, remote_etag TEXT, remote_size INTEGER, remote_mtime INTEGER,
  detected INTEGER, UNIQUE(root_id, rel));
CREATE TABLE IF NOT EXISTS remote(key TEXT PRIMARY KEY, size INTEGER, etag TEXT, mtime INTEGER);
)";

}  // namespace

Db::~Db() {
    if (db_) sqlite3_close(db_);
}

bool Db::exec(const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

bool Db::open(const std::string& path, std::string* error) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    mkdirs(path_dirname(path), 0700);
    if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
        if (error) *error = sqlite3_errmsg(db_);
        return false;
    }
    sqlite3_busy_timeout(db_, 5000);
    if (!exec(kSchema)) {
        if (error) *error = sqlite3_errmsg(db_);
        return false;
    }
    return true;
}

std::vector<RootRow> Db::roots() {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    std::vector<RootRow> r;
    Stmt s(db_, "SELECT id, local_path, remote_prefix, direction, encrypt, paused FROM roots ORDER BY id");
    while (s.step()) {
        RootRow x;
        x.id = int(s.i64(0));
        x.local_path = s.str(1);
        x.remote_prefix = s.str(2);
        x.direction = s.str(3);
        x.encrypt = s.i64(4) != 0;
        x.paused = s.i64(5) != 0;
        r.push_back(x);
    }
    return r;
}

int Db::add_root(const RootRow& r) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    Stmt s(db_, "INSERT INTO roots(local_path, remote_prefix, direction, encrypt, paused) VALUES(?,?,?,?,?)");
    s.bind(1, r.local_path).bind(2, r.remote_prefix).bind(3, r.direction).bind(4, int64_t(r.encrypt)).bind(5, int64_t(r.paused));
    if (!s.run()) return 0;
    return int(sqlite3_last_insert_rowid(db_));
}

bool Db::update_root(const RootRow& r) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    Stmt s(db_, "UPDATE roots SET remote_prefix=?, direction=?, encrypt=?, paused=? WHERE id=?");
    s.bind(1, r.remote_prefix).bind(2, r.direction).bind(3, int64_t(r.encrypt)).bind(4, int64_t(r.paused)).bind(5, int64_t(r.id));
    return s.run();
}

void Db::remove_root(int id) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    Stmt(db_, "DELETE FROM files WHERE root_id=?").bind(1, int64_t(id)).run();
    Stmt(db_, "DELETE FROM conflicts WHERE root_id=?").bind(1, int64_t(id)).run();
    Stmt(db_, "DELETE FROM roots WHERE id=?").bind(1, int64_t(id)).run();
}

std::map<std::string, FileRow> Db::files(int root_id) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    std::map<std::string, FileRow> m;
    Stmt s(db_, "SELECT rel, remote_key, base_etag, base_hash, l_size, l_mtime, l_inode, l_hash FROM files WHERE root_id=?");
    s.bind(1, int64_t(root_id));
    while (s.step()) {
        FileRow f;
        f.rel = s.str(0);
        f.remote_key = s.str(1);
        f.base_etag = s.str(2);
        f.base_hash = s.str(3);
        f.l_size = uint64_t(s.i64(4));
        f.l_mtime = s.i64(5);
        f.l_inode = uint64_t(s.i64(6));
        f.l_hash = s.str(7);
        m[f.rel] = f;
    }
    return m;
}

void Db::upsert_file(int root_id, const FileRow& f) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    Stmt s(db_, "INSERT OR REPLACE INTO files(root_id, rel, remote_key, base_etag, base_hash, l_size, l_mtime, l_inode, l_hash) "
                "VALUES(?,?,?,?,?,?,?,?,?)");
    s.bind(1, int64_t(root_id)).bind(2, f.rel).bind(3, f.remote_key).bind(4, f.base_etag).bind(5, f.base_hash)
        .bind(6, int64_t(f.l_size)).bind(7, f.l_mtime).bind(8, int64_t(f.l_inode)).bind(9, f.l_hash);
    s.run();
}

void Db::delete_file(int root_id, const std::string& rel) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    Stmt(db_, "DELETE FROM files WHERE root_id=? AND rel=?").bind(1, int64_t(root_id)).bind(2, rel).run();
}

static ConflictRow read_conflict(Stmt& s) {
    ConflictRow c;
    c.id = s.i64(0);
    c.root_id = int(s.i64(1));
    c.rel = s.str(2);
    c.kind = s.str(3);
    c.local_exists = s.i64(4) != 0;
    c.local_size = uint64_t(s.i64(5));
    c.local_mtime = s.i64(6);
    c.local_hash = s.str(7);
    c.remote_exists = s.i64(8) != 0;
    c.remote_key = s.str(9);
    c.remote_etag = s.str(10);
    c.remote_size = uint64_t(s.i64(11));
    c.remote_mtime = s.i64(12);
    c.detected = s.i64(13);
    return c;
}

static const char* kConflictCols =
    "id, root_id, rel, kind, local_exists, local_size, local_mtime, local_hash, remote_exists, remote_key, "
    "remote_etag, remote_size, remote_mtime, detected";

std::vector<ConflictRow> Db::conflicts(int root_id) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    std::vector<ConflictRow> r;
    std::string sql = std::string("SELECT ") + kConflictCols + " FROM conflicts" +
                      (root_id ? " WHERE root_id=?" : "") + " ORDER BY root_id, rel";
    Stmt s(db_, sql.c_str());
    if (root_id) s.bind(1, int64_t(root_id));
    while (s.step()) r.push_back(read_conflict(s));
    return r;
}

bool Db::conflict(int64_t id, ConflictRow& out) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    std::string sql = std::string("SELECT ") + kConflictCols + " FROM conflicts WHERE id=?";
    Stmt s(db_, sql.c_str());
    s.bind(1, id);
    if (!s.step()) return false;
    out = read_conflict(s);
    return true;
}

void Db::set_conflicts(int root_id, const std::vector<ConflictRow>& rows) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    exec("BEGIN");
    // Keep ids stable for paths that are still in conflict (the UI holds selections by id).
    std::map<std::string, int64_t> old;
    {
        Stmt s(db_, "SELECT rel, id FROM conflicts WHERE root_id=?");
        s.bind(1, int64_t(root_id));
        while (s.step()) old[s.str(0)] = s.i64(1);
    }
    Stmt(db_, "DELETE FROM conflicts WHERE root_id=?").bind(1, int64_t(root_id)).run();
    for (auto& c : rows) {
        Stmt s(db_, "INSERT INTO conflicts(id, root_id, rel, kind, local_exists, local_size, local_mtime, local_hash, "
                    "remote_exists, remote_key, remote_etag, remote_size, remote_mtime, detected) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
        auto it = old.find(c.rel);
        if (it != old.end()) s.bind(1, it->second);
        else sqlite3_bind_null(s.s, 1);
        s.bind(2, int64_t(root_id)).bind(3, c.rel).bind(4, c.kind).bind(5, int64_t(c.local_exists))
            .bind(6, int64_t(c.local_size)).bind(7, c.local_mtime).bind(8, c.local_hash)
            .bind(9, int64_t(c.remote_exists)).bind(10, c.remote_key).bind(11, c.remote_etag)
            .bind(12, int64_t(c.remote_size)).bind(13, c.remote_mtime).bind(14, c.detected ? c.detected : int64_t(time(nullptr)));
        s.run();
    }
    exec("COMMIT");
}

void Db::delete_conflict(int64_t id) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    Stmt(db_, "DELETE FROM conflicts WHERE id=?").bind(1, id).run();
}

void Db::set_remote_cache(const std::vector<ObjectInfo>& objs, int64_t listed_at) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    exec("BEGIN");
    exec("DELETE FROM remote");
    for (auto& o : objs) {
        Stmt s(db_, "INSERT OR REPLACE INTO remote(key, size, etag, mtime) VALUES(?,?,?,?)");
        s.bind(1, o.key).bind(2, int64_t(o.size)).bind(3, o.etag).bind(4, o.mtime).run();
    }
    exec("COMMIT");
    set_meta("remote_listed_at", std::to_string(listed_at));
}

std::vector<ObjectInfo> Db::remote_cache(int64_t* listed_at) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    std::vector<ObjectInfo> r;
    Stmt s(db_, "SELECT key, size, etag, mtime FROM remote ORDER BY key");
    while (s.step()) {
        ObjectInfo o;
        o.key = s.str(0);
        o.size = uint64_t(s.i64(1));
        o.etag = s.str(2);
        o.mtime = s.i64(3);
        r.push_back(o);
    }
    if (listed_at) *listed_at = atoll(meta("remote_listed_at").c_str());
    return r;
}

std::string Db::meta(const std::string& k) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    Stmt s(db_, "SELECT v FROM meta WHERE k=?");
    s.bind(1, k);
    return s.step() ? s.str(0) : "";
}

void Db::set_meta(const std::string& k, const std::string& v) {
    std::lock_guard<std::recursive_mutex> lk(mu_);
    Stmt(db_, "INSERT OR REPLACE INTO meta(k, v) VALUES(?,?)").bind(1, k).bind(2, v).run();
}

}  // namespace s3v
