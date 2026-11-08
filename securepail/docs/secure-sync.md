# Secure sync

English | [简体中文](secure-sync.zh-CN.md)

Secure sync keeps a local folder and a bucket prefix identical in both directions, optionally encrypted with a [secure layer suite](secure-layer.md). It is separate from the one-way sync jobs: it remembers what each file looked like after the last sync, so it can tell which side changed. Its design follows [s3vault](https://github.com/jstdlee/s3vault).

## Set up

```
pail secure keygen vault-key
pail ssync root add docs ~/Documents/vault s3://my-bucket/vault/ --suite aesgcm --key vault-key
pail ssync run docs
```

- `--suite aesgcm` or `gpg` encrypts files; leave it out for plain files. `--plain GLOB` keeps matching files unencrypted, `--exclude GLOB` never syncs them, `--trash-days N` sets how long deleted files stay in the remote trash (default 30).
- Every device that shares the folder needs the same key: `pail secure export` on one, `pail secure import` on the others.
- `pail ssync run NAME --dry-run` shows what would happen and changes nothing. `pail ssync watch NAME --interval 60s` syncs repeatedly. The desktop app has a **Secure sync** tool (sync, preview, conflicts, remote trash); roots are added on the command line.

## What is stored

Below the prefix: your files (`name`, or `name.spe` / `name.gpg` when encrypted) and a `.securepail/` folder with `vault.json` (a marker, no secrets), `devices/` (one small file per device) and `trash/`. The bucket sees file names, sizes and times, not contents.

## How a sync decides

For each file it compares the local content hash, the remote ETag and what was recorded after the last sync:

| Local | Remote | Action |
|---|---|---|
| same | same | nothing |
| changed | same | upload, only if the remote still has the ETag it saw |
| same | changed | download |
| changed | changed | fetch the remote and compare content: equal is recorded silently, different is a **conflict** |
| deleted | same | remote goes to the remote trash |
| same | deleted | local file goes to the OS trash |
| deleted or changed | changed or deleted | **conflict** |
| new | new | same content check |

Every upload is conditional (`If-Match` / `If-None-Match`). If another device wins a race, the file is planned again, so nothing is overwritten by accident. A download never replaces a local file that was edited after the plan was made, and remote keys that would write outside the folder are skipped with a warning. Encrypted files differ in ciphertext even for equal content, which is why equal content is only confirmed by fetching; above 256 MiB the file is a conflict without the check.

## Conflicts

`pail ssync conflicts NAME` lists them. `pail ssync resolve NAME PATH ACTION`, or the buttons in the desktop tool, settles one:

- `keep-both`: your version becomes `name (conflict <device> <date>).ext`, the remote version takes its place, and the next sync uploads your copy.
- `overwrite-remote`: your version wins (a deletion wins too).
- `overwrite-local`: the remote version wins.
- `keep-newest`: the one with the later modification time wins; if one side was deleted, the surviving file is kept.
- `skip`: leave it.

The decision is made on the current state of both sides, and the writes are conditional, so an out-of-date list cannot cause a wrong write.

## Trash, edit, preview

- **Remote trash.** Deleting a file moves the remote object to `.securepail/trash/<time>/`. `pail ssync trash NAME ls|restore KEY|purge`. Items older than the retention are purged after each sync.
- **Edit.** `pail ssync edit NAME PATH` decrypts the file into a private folder, opens `$VISUAL` or `$EDITOR` and, if you changed it, saves it back only if the remote is unchanged. If the remote changed meanwhile, your edit is saved as a conflict copy. The plaintext is overwritten and removed afterwards. Other apps may keep their own copies.
- **Preview.** `pail ssync preview NAME PATH` decrypts into memory, with caps checked before the download: 2 MB of text, 50 MB or 64 megapixels of image, a hex dump of 64 KB for anything else. Nothing is fetched until you ask.

## Limits

- Local changes are found at each sync (`watch` repeats it); there is no file system watcher.
- Only regular files are synced. Empty folders and symbolic links are not.
- Changing a root's suite does not re-encrypt existing files; a changed file moves to the new key name and the old object goes to the remote trash.
- The password cache modes of s3vault (ask, idle, keychain days) are not repeated: keys live in the key store, or in the encrypted vault when that is the secret backend, which locks after its idle time.
