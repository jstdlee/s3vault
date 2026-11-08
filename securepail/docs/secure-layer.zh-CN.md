# 安全层与就绪检查

[English](secure-layer.md) | 简体中文

## 安全层

上传规则可以加一层安全层：每个文件在上传前先在你的电脑上加密，存储服务只看到密文和文件大小。各层的顺序固定：先压缩，再加密。下载时用 `--decode auto --secure-key REF`，按相反顺序还原。可以与服务端加密（SSE）叠加。

### 选择套件

运行 `pail secure suites` 查看列表。按需要在哪里打开文件来选。

| | AES-256-GCM（可移植） | GPG（OpenPGP） |
|---|---|---|
| 规则中的值 | `aesgcm` | `gpg` |
| 对象键后缀 | `.spe` | `.gpg` |
| 是否需要额外软件 | 否 | gpg 2.2 或更新 |
| 桌面 | 支持 | 支持 |
| iOS 和 Android | 支持（CryptoKit、`javax.crypto`） | 不支持 |
| 大文件 | 分块流式处理；能发现被截断 | 整个数据流 |
| 密钥 | 仅生成的密钥 | 生成的密钥或手动输入的口令 |
| 不用 securePail 打开 | 按下文格式移植 | `gpg -d` |

除非需要标准 OpenPGP 文件，请选 **AES-256-GCM**。同一批文件要在手机上打开时，就用它。

### 密钥

密钥保存在密钥库中，以引用名指定，不会写进规则、日志或对象元数据。

- `pail secure keygen REF` 生成随机的 256 位密钥（上传规则里也可点**新建密钥**）。
- `pail secure passphrase REF` 在强度检查后保存手动输入的口令。只有 GPG 接受口令，且有意放慢（每个文件约 150 毫秒）。
- `pail secure export REF FILE` 写出受密码保护的密钥文件。默认的 `keyfile` 格式是 JSON（PBKDF2-HMAC-SHA256，600,000 轮，AES-256-GCM），不需要任何工具；`--format gpg` 写出可用 `gpg -d` 打开的文件。
- `pail secure recovery REF` 把密钥显示为 16 组、每组 4 位十六进制数，便于抄写或在手机上输入。
- `pail secure import REF FILE` 从密钥文件（两种格式均可）或恢复密钥恢复。密钥不会被覆盖。没有密钥，加密的数据无法恢复。

### 出错即停

缺少必需的工具或密钥时上传失败，绝不退回明文。下载时遇到密钥错误、数据损坏或格式不符，会拒绝并且不保存任何文件。

### 限制

- 加密上传会先生成与原文件等大的临时文件。
- 同步任务的校验和比较无法匹配加密对象（每次加密结果都不同），请用大小和时间。
- 下载的文件保留 `.spe` 或 `.gpg` 文件名。

### 可移植套件的格式

供移植到其他平台的人参考，只需要 HKDF-SHA256、AES-256-GCM 和 PBKDF2-HMAC-SHA256。

```
对象     = 头部 | 块 0 | 块 1 | ...
头部     = "SPE1" | 块大小（uint32 大端，1 KiB 到 16 MiB，默认 1 MiB）| 盐（16 字节随机数）
文件密钥 = HKDF-SHA256(ikm = 主密钥, salt = 盐, info = "securepail-file-v1", 32 字节)
块 i     = AES-256-GCM(文件密钥, nonce = uint32 大端(i) | 7 个零字节 | last, aad = 头部, 明文最多 块大小 字节)
           存储为 密文 | 16 字节标签
```

最后一块的 `last` 为 1，其余为 0；只有最后一块可以较短，空文件是一个空块。每个文件使用新的盐，因此各有自己的密钥。

密钥文件是 JSON，`format` 为 `securepail-key`，`version` 为 1，`kdf` 为 `PBKDF2-HMAC-SHA256`，另有 `iterations`、`salt`、`wrappedKey`（AES-GCM 的 nonce、密文和标签；关联数据为 `securepail-key-v1`）和 `check`（以主密钥对 `securepail-check` 做 HMAC-SHA256，取前 16 字节）。密码先做 NFC 规范化。它沿用 Quick Diary 应用的密钥文件结构，标签是自己的。

`internal/seclayer/testdata/portable-vectors.json` 是已知答案测试向量。`python3 scripts/check-portable-vectors.py` 用另一套实现（Python 的 `cryptography` 包）解密它们；移植版本应通过同样的向量。

## 就绪检查

`pail doctor` 检查安全层依赖的组件，并告诉你每个问题怎么修：gpg（是否找到、版本 2.2 或更新）、一次真实的加密解密往返（能发现禁止非交互使用的 gpg-agent）、gpg-agent、系统密钥库和临时目录。只有启用的规则用到 GPG 套件时，gpg 才算必需；想在启用前检查，加 `--require-gpg`。必需组件失败时退出码为 1；`--json` 每项检查输出一个事件。桌面版的上传规则在选择安全层后显示同样的检查（**检查组件**）。设置 `SECUREPAIL_GPG` 可指定 gpg 的路径。

### 服务器和没有桌面的机器

密钥保存在系统密钥库中。没有桌面的 Linux 机器（服务器、树莓派）没有密钥库，`pail doctor` 会报告密钥库失败。请改用加密保险库：先 `pail vault init`，再 `pail vault backend vault`，需要密钥的命令（`secure`、`doctor`、`cp`、`ssync`）加上 `--vault-password-stdin`。这时 AES-256-GCM 套件不需要安装任何其他东西。在 Linux x64 和 Arm 上做法相同。

## 来源

securePail 是 Dejavu Moe 的 [Pail](https://github.com/DejavuMoe/Pail) 的分支，沿用同样的技术栈（Go 和 [MyGo](https://github.com/egoist/mygo)）。GPG 套件参考 [s3vault](https://github.com/jstdlee/s3vault) 的设计，可移植套件参考 [Quick Diary](https://github.com/jstdlee/quick-diary)。保持 MIT 许可证。它的配置目录和密钥库条目都叫 `securePail`，可以与 Pail 并存。
