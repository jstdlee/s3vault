# 安全同步

[English](secure-sync.md) | 简体中文

安全同步让本地文件夹和存储桶里的一个前缀双向保持一致，并可用[安全层套件](secure-layer.zh-CN.md)加密。它与单向同步任务相互独立：它记住每个文件上次同步后的样子，因此能分辨是哪一边改了。设计参考 [s3vault](https://github.com/jstdlee/s3vault)。

## 设置

```
pail secure keygen vault-key
pail ssync root add docs ~/Documents/vault s3://my-bucket/vault/ --suite aesgcm --key vault-key
pail ssync run docs
```

- `--suite aesgcm` 或 `gpg` 会加密文件；省略则保持明文。`--plain GLOB` 让匹配的文件不加密，`--exclude GLOB` 让它们永不同步，`--trash-days N` 设置删除的文件在远端回收站保留多久（默认 30 天）。
- 共用这个文件夹的每台设备都需要同一个密钥：在一台上 `pail secure export`，在其他设备上 `pail secure import`。
- `pail ssync run NAME --dry-run` 只显示会做什么，不改任何东西。`pail ssync watch NAME --interval 60s` 反复同步。桌面版有**安全同步**工具（同步、预览、冲突、远端回收站）；添加文件夹要在命令行进行。

## 存了什么

前缀下是你的文件（加密时是 `name.spe` 或 `name.gpg`）和一个 `.securepail/` 文件夹，里面有 `vault.json`（标记，不含机密）、`devices/`（每台设备一个小文件）和 `trash/`。存储桶能看到文件名、大小和时间，看不到内容。

## 同步如何判断

对每个文件，它比较本地内容哈希、远端 ETag，以及上次同步后记录的状态：

| 本地 | 远端 | 动作 |
|---|---|---|
| 相同 | 相同 | 不做 |
| 已改 | 相同 | 上传，且仅当远端仍是它看到的 ETag |
| 相同 | 已改 | 下载 |
| 已改 | 已改 | 取回远端并比较内容：相同则静默记录，不同则为**冲突** |
| 已删除 | 相同 | 远端进入远端回收站 |
| 相同 | 已删除 | 本地文件进入系统回收站 |
| 已删除或已改 | 已改或已删除 | **冲突** |
| 新增 | 新增 | 同样做内容检查 |

每次上传都是有条件的（`If-Match` / `If-None-Match`）。如果另一台设备抢先一步，该文件会重新规划，所以不会意外覆盖。下载不会替换在制定计划之后又被编辑过的本地文件；会写到文件夹之外的远端键会被跳过并给出警告。加密文件即使内容相同，密文也不同，所以只能通过取回来确认内容相同；超过 256 MiB 时不做检查，直接算冲突。

## 冲突

`pail ssync conflicts NAME` 列出冲突。用 `pail ssync resolve NAME PATH ACTION`，或桌面工具里的按钮来处理：

- `keep-both`：你的版本变成 `name (conflict <设备> <日期>).ext`，远端版本回到原位，下次同步会上传你的副本。
- `overwrite-remote`：你的版本获胜（删除也算获胜）。
- `overwrite-local`：远端版本获胜。
- `keep-newest`：修改时间较晚的获胜；如果有一边已被删除，则保留还存在的文件。
- `skip`：不处理。

决定依据两边当前的状态做出，写入又是有条件的，所以过时的列表不会造成错误写入。

## 回收站、编辑、预览

- **远端回收站。** 删除文件会把远端对象移到 `.securepail/trash/<时间>/`。`pail ssync trash NAME ls|restore KEY|purge`。超过保留期的项目在每次同步后清除。
- **编辑。** `pail ssync edit NAME PATH` 把文件解密到私有文件夹，打开 `$VISUAL` 或 `$EDITOR`；如果你改了，只有远端未变时才保存回去。如果远端在此期间变了，你的编辑会存为冲突副本。之后明文会被覆盖并删除。其他应用可能保留自己的副本。
- **预览。** `pail ssync preview NAME PATH` 解密到内存，大小上限在下载前检查：文本 2 MB，图片 50 MB 或 64 百万像素，其他类型显示 64 KB 的十六进制。你不要求，就不会取回任何内容。

## 限制

- 本地改动在每次同步时发现（`watch` 会重复同步）；没有文件系统监视器。
- 只同步普通文件，不同步空文件夹和符号链接。
- 更改文件夹的套件不会重新加密已有文件；改动过的文件会换成新的键名，旧对象进入远端回收站。
- 没有照搬 s3vault 的口令缓存模式（每次询问、空闲、钥匙串天数）：密钥保存在密钥库中，或在以加密保险库为机密后端时保存在其中，它会在空闲一段时间后锁定。
