#include "sync/planner.h"

#include <set>

#include "util/strings.h"

namespace s3v {

std::string upload_key(const PlanInput& in, const std::string& rel, const RemoteFile* remote, const FileRow* base) {
    // Keep an existing object's form (plain vs encrypted); new files follow the root default.
    // Local files already named *.gpg are always encrypted, so the suffix stays unambiguous.
    bool enc = in.default_encrypt;
    if (remote) enc = remote->encrypted;
    else if (base && !base->remote_key.empty()) enc = ends_with(base->remote_key, ".gpg");
    if (ends_with(rel, ".gpg")) enc = true;
    std::string logical = in.remote_prefix.empty() ? rel : in.remote_prefix + "/" + rel;
    return in.vault_prefix + logical + (enc ? ".gpg" : "");
}

std::vector<Action> plan_sync(const PlanInput& in) {
    std::set<std::string> paths;
    for (auto& [k, v] : in.local) paths.insert(k);
    for (auto& [k, v] : in.remote) paths.insert(k);
    for (auto& [k, v] : in.base) paths.insert(k);

    bool can_up = in.direction != "download-only";
    bool can_down = in.direction != "upload-only";
    std::vector<Action> out;

    for (auto& rel : paths) {
        auto li = in.local.find(rel);
        auto ri = in.remote.find(rel);
        auto bi = in.base.find(rel);
        const LocalFile* L = li == in.local.end() ? nullptr : &li->second;
        const RemoteFile* R = ri == in.remote.end() ? nullptr : &ri->second;
        const FileRow* B = bi == in.base.end() || bi->second.base_etag.empty() ? nullptr : &bi->second;

        auto act = [&](ActKind k) {
            Action a;
            a.kind = k;
            a.rel = rel;
            return a;
        };
        auto upload = [&](const RemoteFile* r) {
            if (!can_up) return;
            Action a = act(ActKind::Upload);
            a.key = upload_key(in, rel, r, B);
            if (r) {
                a.key = r->key;
                a.if_match = r->etag;
            } else {
                a.if_none_match = true;
            }
            out.push_back(a);
        };
        auto download = [&]() {
            if (!can_down) return;
            Action a = act(ActKind::Download);
            a.key = R->key;
            out.push_back(a);
        };
        auto conflict = [&](const char* kind) {
            Action a = act(ActKind::Conflict);
            a.key = R ? R->key : (B ? B->remote_key : "");
            a.conflict_kind = kind;
            out.push_back(a);
        };

        if (B) {
            bool lchg = L && L->hash != B->base_hash;
            bool rchg = R && R->etag != B->base_etag;
            if (L && R) {
                if (!lchg && !rchg) continue;
                if (lchg && !rchg) upload(R);
                else if (!lchg && rchg) download();
                else {
                    Action a = act(ActKind::CheckEqual);
                    a.key = R->key;
                    a.conflict_kind = "both-modified";
                    out.push_back(a);
                }
            } else if (L && !R) {
                // Deleted on the server.
                if (!lchg) {
                    if (can_down) out.push_back(act(ActKind::DeleteLocal));
                } else {
                    conflict("remote-deleted");
                }
            } else if (!L && R) {
                // Deleted locally.
                if (!rchg) {
                    if (in.direction == "two-way") {
                        Action a = act(ActKind::DeleteRemote);
                        a.key = R->key;
                        a.if_match = R->etag;
                        out.push_back(a);
                    } else if (in.direction == "download-only") {
                        download();  // mirror: the server copy wins
                    }
                    // upload-only (backup): local deletions are not propagated.
                } else if (!can_up) {
                    download();
                } else {
                    conflict("local-deleted");
                }
            } else {
                out.push_back(act(ActKind::ForgetBase));
            }
        } else {
            if (L && R) {
                Action a = act(ActKind::CheckEqual);
                a.key = R->key;
                a.conflict_kind = "both-added";
                out.push_back(a);
            } else if (L) {
                upload(nullptr);
            } else if (R) {
                download();
            } else if (bi != in.base.end()) {
                out.push_back(act(ActKind::ForgetBase));
            }
        }
    }
    return out;
}

}  // namespace s3v
