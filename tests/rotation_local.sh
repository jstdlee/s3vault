#!/usr/bin/env bash
# End-to-end test of `rotate-key` (vault key replacement) against a local S3 server (moto), two simulated
# devices. Needs: build/s3vault-cli, gpg, and moto_server on PATH (pip install "moto[server]"), or
# S3VAULT_TEST_ENDPOINT pointing at an S3 server with an empty bucket "rotation-test".
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
cli="${S3VAULT_CLI:-$here/build/s3vault-cli}"
helper="$(dirname "$cli")/s3vault-it-helper"
work="$(mktemp -d /tmp/s3vault-rot.XXXXXX)"
pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  \e[32mok\e[0m   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  \e[31mFAIL\e[0m %s\n' "$1"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }

endpoint="${S3VAULT_TEST_ENDPOINT:-}"
if [ -z "$endpoint" ]; then
    port=$((20000 + RANDOM % 20000))
    moto_server -p "$port" >"$work/moto.log" 2>&1 &
    moto_pid=$!
    endpoint="http://127.0.0.1:$port"
    for _ in $(seq 50); do curl -s "$endpoint" >/dev/null && break; sleep 0.2; done
    curl -s -X PUT "$endpoint/rotation-test" >/dev/null
fi
cleanup() { [ -n "${moto_pid:-}" ] && kill "$moto_pid" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT

export S3VAULT_SECRET_KEY=test-secret
OLD='Juniper-Lantern-Orbit-7731'
NEW='Copper-Meadow-Harbor-5208'
A() { S3VAULT_HOME="$work/homeA" "$cli" "$@"; }
B() { S3VAULT_HOME="$work/homeB" "$cli" "$@"; }
for d in A B; do
    mkdir -p "$work/home$d" "$work/dir$d"
    for kv in storage.provider=minio "storage.endpoint=$endpoint" storage.bucket=rotation-test storage.access_key_id=test \
              storage.prefix=rot "sync.device_name=device$d" security.remember=idle; do
        S3VAULT_HOME="$work/home$d" "$cli" config set "${kv%%=*}" "${kv#*=}" >/dev/null
    done
done
dA="$work/dirA"; dB="$work/dirB"
H() { S3VAULT_HOME="$work/homeA" "$helper" "$@"; }
exists() { H head "$1" >/dev/null 2>&1; }
gpg_dec() { gpg --batch --quiet --pinentry-mode loopback --passphrase "$1" -d "$2" 2>/dev/null; }

echo "== setup"
check "init" 'S3VAULT_PASSWORD="$OLD" A init >/dev/null'
echo "first note" > "$dA/note.md"
for i in $(seq 1 30); do echo "file $i $RANDOM" > "$dA/f$i.txt"; done
head -c 70000000 /dev/urandom > "$dA/big.bin"   # > 64 MB: re-encrypted through temp files
sleep 2.2  # the scanner skips files modified < 2 s ago
check "A: add-root + sync" 'S3VAULT_PASSWORD="$OLD" A add-root "$dA" --remote docs >/dev/null && S3VAULT_PASSWORD="$OLD" A sync >/dev/null'
echo "deleted later" > "$work/gone.txt"
check "trash: put + rm" 'S3VAULT_PASSWORD="$OLD" A put "$work/gone.txt" gone.txt >/dev/null && S3VAULT_PASSWORD="$OLD" A rm gone.txt >/dev/null'
check "B: add-root + sync" 'S3VAULT_PASSWORD="$OLD" B add-root "$dB" --remote docs >/dev/null && S3VAULT_PASSWORD="$OLD" B sync >/dev/null && cmp -s "$dA/big.bin" "$dB/big.bin"'
check "old recovery key exported" 'S3VAULT_PASSWORD="$OLD" A export-key "$work/old-recovery.txt" --recovery 2>/dev/null'
oldkey=$(tail -1 "$work/old-recovery.txt")
check "old key.gpg exported" 'A export-key "$work/old-key.gpg" >/dev/null'
mkdir -p "$work/asis"
H get-raw docs/note.md.gpg "$work/asis/note-before.gpg"
check "old recovery key opens a file (before)" '[ "$(gpg_dec "$oldkey" "$work/asis/note-before.gpg")" = "first note" ]'

echo "== guard rails"
check "refuses without --recovery-out" '! S3VAULT_OLD_PASSWORD="$OLD" S3VAULT_NEW_PASSWORD="$NEW" A rotate-key --yes </dev/null >/dev/null 2>&1'
check "refuses without a terminal or --yes" '! S3VAULT_OLD_PASSWORD="$OLD" S3VAULT_NEW_PASSWORD="$NEW" A rotate-key --recovery-out "$work/x.txt" </dev/null >/dev/null 2>&1'
check "refuses a wrong current password" '! S3VAULT_OLD_PASSWORD="wrong-wrong-wrong-1" S3VAULT_NEW_PASSWORD="$NEW" A rotate-key --recovery-out "$work/x.txt" --yes >/dev/null 2>&1'
check "refuses the same password" '! S3VAULT_OLD_PASSWORD="$OLD" S3VAULT_NEW_PASSWORD="$OLD" A rotate-key --recovery-out "$work/x.txt" --yes >/dev/null 2>&1'
check "refuses a weak new password" '! S3VAULT_OLD_PASSWORD="$OLD" S3VAULT_NEW_PASSWORD="short" A rotate-key --recovery-out "$work/x.txt" --yes >/dev/null 2>&1'
check "interactive: wrong answer to [1/3] cancels" '! script -qec "S3VAULT_HOME=$work/homeA S3VAULT_OLD_PASSWORD=$OLD S3VAULT_NEW_PASSWORD=$NEW $cli rotate-key --recovery-out $work/y.txt" /dev/null <<<"no" >/dev/null 2>&1'
check "nothing changed so far" '[ "$(S3VAULT_PASSWORD="$OLD" A cat docs/note.md)" = "first note" ] && ! exists .s3vault/rotation.json'

echo "== rotate, paused half way (Ctrl-C)"
S3VAULT_OLD_PASSWORD="$OLD" S3VAULT_NEW_PASSWORD="$NEW" timeout --preserve-status -s INT 2 \
    "$cli" --home "$work/homeA" rotate-key --recovery-out "$work/new-recovery.txt" --yes >"$work/rot1.log" 2>&1
rc=$?
check "paused (exit 3) or finished" '[ $rc -eq 3 ] || [ $rc -eq 0 ]'
check "new recovery key file is mode 600" '[ "$(stat -c %a "$work/new-recovery.txt")" = 600 ]'
newkey=$(tail -1 "$work/new-recovery.txt")
if [ $rc -eq 3 ]; then
    check "marker on the server while paused" 'exists .s3vault/rotation.json'
    check "status shows it" 'A rotate-key --status | grep -q "in progress"'
    check "B can't unlock meanwhile (old password)" '! S3VAULT_PASSWORD="$OLD" B sync >/dev/null 2>&1'
    check "resume refuses the OLD password" '! S3VAULT_NEW_PASSWORD="$OLD" A rotate-key --resume >/dev/null 2>&1'
    check "resume with the NEW password" 'S3VAULT_NEW_PASSWORD="$NEW" A rotate-key --resume >"$work/rot2.log" 2>&1'
    grep -q "already on the new key" "$work/rot2.log" && ok "resume skipped files already done" || bad "resume skipped files already done"
fi
check "marker and key-next removed" '! exists .s3vault/rotation.json && ! exists .s3vault/key-next.gpg'

echo "== after"
check "new password opens files" '[ "$(S3VAULT_PASSWORD="$NEW" A cat docs/note.md)" = "first note" ]'
check "old password refused" '! S3VAULT_PASSWORD="$OLD" A cat docs/note.md >/dev/null 2>&1'
H get-raw docs/note.md.gpg "$work/asis/note-after.gpg"
check "OLD recovery key no longer opens the file" '! gpg_dec "$oldkey" "$work/asis/note-after.gpg" >/dev/null'
check "NEW recovery key opens it with plain gpg" '[ "$(gpg_dec "$newkey" "$work/asis/note-after.gpg")" = "first note" ]'
check "old key.gpg + old password → old key only (useless now)" '[ "$(gpg_dec "$OLD" "$work/old-key.gpg" | tail -1)" = "$oldkey" ]'
check "big file intact" 'S3VAULT_PASSWORD="$NEW" A get docs/big.bin "$work/big.out" >/dev/null && cmp -s "$dA/big.bin" "$work/big.out"'
check "trash re-encrypted too" 'S3VAULT_PASSWORD="$NEW" A trash | grep -q gone.txt && S3VAULT_PASSWORD="$NEW" A restore 1 >/dev/null && [ "$(S3VAULT_PASSWORD="$NEW" A cat gone.txt)" = "deleted later" ]'
S3VAULT_PASSWORD="$NEW" A sync >"$work/syncA.log" 2>&1
check "A: next sync downloads nothing (base ETags followed)" '! grep -qE "[1-9][0-9]* downloaded" "$work/syncA.log"'
check "B: old password refused" '! S3VAULT_PASSWORD="$OLD" B sync >/dev/null 2>&1'
echo "edit on B" >> "$dB/note.md"; sleep 2.2
check "B: new password syncs" 'S3VAULT_PASSWORD="$NEW" B sync >/dev/null && cmp -s "$dA/big.bin" "$dB/big.bin"'
check "B's edit uses the new key" 'S3VAULT_PASSWORD="$NEW" A sync >/dev/null && grep -q "edit on B" "$dA/note.md" && H get-raw docs/note.md.gpg "$work/asis/n3.gpg" && gpg_dec "$newkey" "$work/asis/n3.gpg" | grep -q "edit on B"'
echo "== a device that stays unlocked (watch) while the key is replaced elsewhere"
B config set sync.poll_seconds 10 >/dev/null
S3VAULT_PASSWORD="$NEW" B watch >"$work/watchB.log" 2>&1 &
watch_pid=$!
sleep 4
check "rotate on A while B watches" 'S3VAULT_OLD_PASSWORD="$NEW" S3VAULT_NEW_PASSWORD="$NEW-2" A rotate-key --recovery-out "$work/r2.txt" --yes >/dev/null 2>&1'
newkey2=$(tail -1 "$work/r2.txt")
sleep 12   # B's next poll sees the new key-check and drops its (old) key
echo "written on B after the replacement" >> "$dB/note.md"
sleep 14   # the watcher would upload now, if it still had a key
kill $watch_pid 2>/dev/null; wait $watch_pid 2>/dev/null
check "B paused encrypted files (key dropped)" 'grep -q "vault locked" "$work/watchB.log"'
H get-raw docs/note.md.gpg "$work/asis/n4.gpg"
check "nothing on the server is encrypted with the old key" 'gpg_dec "$newkey2" "$work/asis/n4.gpg" >/dev/null && ! grep -q "written on B after" <(gpg_dec "$newkey2" "$work/asis/n4.gpg")'
check "B uploads the edit after unlocking with the new password" 'sleep 2.2; S3VAULT_PASSWORD="$NEW-2" B sync >/dev/null && H get-raw docs/note.md.gpg "$work/asis/n5.gpg" && gpg_dec "$newkey2" "$work/asis/n5.gpg" | grep -q "written on B after"'
NEW="$NEW-2"

check "a third rotation works" 'S3VAULT_OLD_PASSWORD="$NEW" S3VAULT_NEW_PASSWORD="$OLD-2" A rotate-key --recovery-out "$work/r3.txt" --yes >/dev/null 2>&1 && [ "$(S3VAULT_PASSWORD="$OLD-2" A cat docs/note.md | head -1)" = "first note" ]'

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
