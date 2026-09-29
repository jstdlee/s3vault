#!/usr/bin/env bash
# End-to-end test against a real S3-compatible bucket (written for Cloudflare R2), two simulated devices.
#
# Needs ~/.config/s3vault/test.env (mode 600) with:
#   S3VAULT_TEST_PROVIDER=r2  S3VAULT_TEST_ACCOUNT_ID=…  S3VAULT_TEST_BUCKET=…
#   S3VAULT_TEST_ACCESS_KEY_ID=…  S3VAULT_TEST_SECRET_KEY=…
# Everything happens under s3vault-it/<random>/ in the bucket and is deleted at the end.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cli="$here/build/s3vault-cli"
helper="$here/build/s3vault-it-helper"
env_file="${S3VAULT_TEST_ENV:-$HOME/.config/s3vault/test.env}"
[ -f "$env_file" ] || { echo "missing $env_file"; exit 2; }
set -a; . "$env_file"; set +a

run_id="$(date +%s)-$RANDOM"
work="$(mktemp -d /tmp/s3vault-it.XXXXXX)"
export S3VAULT_SECRET_KEY="$S3VAULT_TEST_SECRET_KEY"
export S3VAULT_PASSWORD="Integration-Test-pw-$RANDOM-Vault!"
pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  \e[32mok\e[0m   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  \e[31mFAIL\e[0m %s\n' "$1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
A() { S3VAULT_HOME="$work/homeA" "$cli" "$@"; }
B() { S3VAULT_HOME="$work/homeB" "$cli" "$@"; }
H() { S3VAULT_HOME="$work/homeA" "$helper" "$@"; }
settle() { sleep 2.2; }  # the scanner skips files modified < 2 s ago

cleanup() {
    H wipe >/dev/null 2>&1
    rm -rf "$work"
}
trap cleanup EXIT

for d in A B; do
    home="$work/home$d"
    mkdir -p "$home" "$work/dir$d"
    S3VAULT_HOME="$home" "$cli" config set storage.provider "$S3VAULT_TEST_PROVIDER"
    S3VAULT_HOME="$home" "$cli" config set storage.account_id "$S3VAULT_TEST_ACCOUNT_ID"
    S3VAULT_HOME="$home" "$cli" config set storage.bucket "$S3VAULT_TEST_BUCKET"
    S3VAULT_HOME="$home" "$cli" config set storage.access_key_id "$S3VAULT_TEST_ACCESS_KEY_ID"
    S3VAULT_HOME="$home" "$cli" config set storage.prefix "s3vault-it/$run_id"
    S3VAULT_HOME="$home" "$cli" config set sync.device_name "device$d"
done
dA="$work/dirA"; dB="$work/dirB"

echo "== storage probe"
check "probe (auth, conditional writes, copy, multipart)" 'A probe --multipart >"$work/probe.txt" 2>&1'
sed 's/^/     /' "$work/probe.txt"

echo "== vault"
check "weak password refused" '! S3VAULT_PASSWORD=short A init >/dev/null 2>&1'
check "init with password" 'A init >/dev/null'
check "second init refused (If-None-Match)" '! A init >/dev/null 2>&1'
check "wrong password refused" '! S3VAULT_PASSWORD="nope-nope-nope-1A" A sync >/dev/null 2>&1'

echo "== initial sync A → B"
mkdir -p "$dA/sub/deep" "$dA/.git"
echo "hello from A" > "$dA/notes.md"
head -c 300000 /dev/urandom > "$dA/sub/blob.bin"
printf '中文 文件名\n' > "$dA/sub/deep/中文.txt"
echo "already gpg" > "$dA/key.gpg"
echo "ignored" > "$dA/.DS_Store"
echo "tmp" > "$dA/x.swp"
settle
A add-root "$dA" --remote docs >/dev/null
B add-root "$dB" --remote docs >/dev/null
check "A sync uploads" 'A sync >"$work/s1" 2>&1 && grep -q "4 up" "$work/s1"'
check "objects are encrypted (.gpg keys)" 'H head docs/notes.md.gpg >/dev/null && ! H head docs/notes.md >/dev/null 2>&1'
check "*.gpg file double-encrypted" 'H head docs/key.gpg.gpg >/dev/null'
check "ignored files not uploaded" '! H head docs/.DS_Store.gpg >/dev/null 2>&1'
check "B sync downloads" 'B sync >"$work/s2" 2>&1 && grep -q "4 down" "$work/s2"'
check "trees equal after sync" 'diff -r --exclude=.DS_Store --exclude=x.swp --exclude=.git "$dA" "$dB"'
check "second sync is a no-op" 'A sync | grep -q "^0 up, 0 down"'

echo "== changes both ways"
settle
echo "edited on B" >> "$dB/notes.md"; settle
check "B uploads edit" 'B sync | grep -q "1 up"'
check "A downloads edit" 'A sync | grep -q "1 down" && grep -q "edited on B" "$dA/notes.md"'
rm "$dA/sub/blob.bin"; settle
check "A deletes remotely" 'A sync | grep -q "1 deleted remote"'
check "B deletes locally" 'B sync | grep -q "1 deleted local" && [ ! -e "$dB/sub/blob.bin" ]'
check "deleted file is in vault trash" 'A trash | grep -q "docs/sub/blob.bin"'

echo "== conflicts"
settle
echo "A version" > "$dA/notes.md"; echo "B version" > "$dB/notes.md"; settle
A sync >/dev/null
check "B detects both-modified conflict" 'B sync | grep -q "1 conflicts" && B conflicts | grep -q both-modified'
id=$(B conflicts | awk 'NR==1{print $1}')
check "resolve keep-both" 'B resolve "$id" keep-both >/dev/null'
check "B has both versions" 'grep -q "B version" "$dB/notes.md" && cat "$dB"/notes\ \(conflict\ remote*.md | grep -q "A version"'
check "A gets both after sync" 'A sync >/dev/null && grep -q "B version" "$dA/notes.md" && ls "$dA" | grep -q "notes (conflict remote"'
settle
echo "same" > "$dA/same.txt"; echo "same" > "$dB/same.txt"; settle
A sync >/dev/null
check "identical content on both sides is not a conflict" 'B sync | grep -q "0 conflicts"'
settle
rm "$dA/same.txt"; echo "changed on B" > "$dB/same.txt"; settle
A sync >/dev/null
check "modify vs delete is a conflict" 'B sync | grep -q "1 conflicts" && B conflicts | grep -q remote-deleted'
id=$(B conflicts | awk 'NR==1{print $1}')
check "resolve keep-local restores it on the server" 'B resolve "$id" keep-local >/dev/null && A sync >/dev/null && grep -q "changed on B" "$dA/same.txt"'

echo "== race: conditional write protects concurrent updates"
settle
echo "base" > "$dA/race.txt"; settle; A sync >/dev/null; B sync >/dev/null
settle
echo "A2" > "$dA/race.txt"; echo "B2" > "$dB/race.txt"; settle
A sync >/dev/null & B sync >/dev/null & wait
A sync >/dev/null; B sync >/dev/null
check "one side reports the conflict, nothing lost" '(A conflicts; B conflicts) | grep -q race.txt'

echo "== vault file operations (CLI)"
echo "manual upload" > "$work/manual.txt"
check "put (encrypted by default)" 'A put "$work/manual.txt" inbox/manual.txt >/dev/null 2>&1 && H head inbox/manual.txt.gpg >/dev/null'
check "put refuses to overwrite" '! A put "$work/manual.txt" inbox/manual.txt >/dev/null 2>&1'
check "put --plain" 'A put "$work/manual.txt" inbox/plain.txt --plain >/dev/null 2>&1 && H head inbox/plain.txt >/dev/null'
check "cat decrypts" 'A cat inbox/manual.txt | grep -q "manual upload"'
check "ls sorts and shows folders" 'A ls --sort size >"$work/ls" && grep -q "Folder.*docs/" "$work/ls" && grep -q "inbox/" "$work/ls"'
check "mkdir" 'A mkdir inbox/empty && A ls inbox | grep -q "inbox/empty/"'
check "mv" 'A mv inbox/manual.txt inbox/moved.txt && A cat inbox/moved.txt | grep -q "manual upload"'
check "get" 'A get inbox/moved.txt "$work/got.txt" >/dev/null && cmp -s "$work/got.txt" "$work/manual.txt"'
check "rm → trash → restore" 'A rm inbox/moved.txt >/dev/null && n=$(A trash | grep -n "inbox/moved.txt" | head -1 | awk "{print \$1}") && A restore "$n" >/dev/null && A cat inbox/moved.txt | grep -q manual'

echo "== tamper and password checks"
printf 'planted' | gpg --batch --store -o "$work/lit.gpg" 2>/dev/null
H put-raw inbox/planted.txt.gpg "$work/lit.gpg"
check "planted unencrypted .gpg object is refused" '! A cat inbox/planted.txt >/dev/null 2>&1'
check "password change keeps files readable" 'S3VAULT_OLD_PASSWORD="$S3VAULT_PASSWORD" S3VAULT_PASSWORD="$S3VAULT_PASSWORD-new" A passwd >/dev/null && S3VAULT_PASSWORD="$S3VAULT_PASSWORD-new" A cat docs/notes.md | grep -q "B version"'
check "old password no longer works" '! A cat docs/notes.md >/dev/null 2>&1'
export S3VAULT_PASSWORD="$S3VAULT_PASSWORD-new"

echo "== large file (multipart through sync)"
head -c $((70*1024*1024)) /dev/urandom > "$dA/big.bin"; settle
check "70 MiB encrypted upload" 'A sync | grep -q "1 up"'
check "70 MiB download + decrypt matches" 'B sync >/dev/null && cmp -s "$dA/big.bin" "$dB/big.bin"'

echo "== plain root"
mkdir -p "$work/plainA"; echo "not secret" > "$work/plainA/readme.txt"; settle
A add-root "$work/plainA" --remote public --plain >/dev/null
check "plain root uploads without .gpg" 'A sync >/dev/null && H head public/readme.txt >/dev/null'

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
