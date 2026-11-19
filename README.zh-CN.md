# Termius MCP Rust

[English](README.md) · [简体中文](README.zh-CN.md)

原生 Rust 编写的 Termius Cloud MCP 服务器，提供云端主机查询、SSH 执行和
SFTP 文件操作。基于上传的 **Termius MCP 3.2.0** 源码快照移植，原项目为
[MiaM1ku/termius-mcp](https://github.com/MiaM1ku/termius-mcp)。本项目与 Termius
官方无隶属或背书关系。

运行时不依赖 Python，不调用系统 `ssh` / `sftp` 子进程；SSH 使用 `russh`，
SFTP 使用 `russh-sftp`。

## 当前状态

Rust 版本包含独立密码学测试向量、MCP 协议集成测试和临时本地
OpenSSH 服务实测。**真实 Termius 账号登录、Google SSO、团队保险库同步及桌面
系统钥匙串仍需真实环境验证。** 云端协议来自兼容 Termius 桌面 10.0.6 的上传
源码，不代表官方承诺稳定的公共 API。

详见 [移植差异](docs/PORTING.md) 和 [独立审查报告](docs/REVIEW.md)。

## 安装

从 [GitHub Releases](https://github.com/chummumm/termius-mcp-rs/releases/latest)
下载对应系统的编译包，解压后将所在目录加入 `PATH`，或在 MCP 客户端中使用
可执行文件的绝对路径。每个包都提供 Python 原版的 `termius`、`termius-mcp`
两个入口，Windows 下扩展名为 `.exe`。运行编译包不需要安装 Rust 或 Python。
发布页附有 `SHA256SUMS`，压缩包内包含第三方依赖许可。

### 从源码编译

需要 Rust **1.89 或更高版本**。从 [rustup.rs](https://rustup.rs/) 安装工具链后：

```sh
git clone https://github.com/chummumm/termius-mcp-rs.git
cd termius-mcp-rs
cargo install --path . --locked
termius login
```

与 Python 原版一致，`termius` 和 `termius-mcp` 都运行同一套 CLI 和 stdio 服务，
不提供 `termius-mcp-rs` 命令。如果同时安装了 Python 版，用绝对路径或 `PATH`
顺序选择要运行的程序。Rust 数据目录仍为 **`~/.termius-rs`**，与 Python 的
`~/.termius` 分开，需要重新登录。可用 `TERMIUS_DATA_DIR` 环境变量另选目录。

### 配置 MCP 客户端

启动命令不加子命令，**不要把 `login` 放进 MCP 的 args**：

```json
{
  "mcpServers": {
    "termius": {
      "command": "termius",
      "args": []
    }
  }
}
```

客户端找不到程序时，将 `command` 改成可执行文件的绝对路径。
Codex 配置示例：

```toml
[mcp_servers.termius]
command = "termius"
args = []
startup_timeout_sec = 30.0
tool_timeout_sec = 240.0
```

支持原版使用的 MCP `2025-11-25` 和 `2025-06-18`。需要先完成 `initialize`
及 `notifications/initialized`。输出为 JSONL，输入也兼容旧式
`Content-Length` 帧；不宣称兼容不同机制的 `2026-07-28` 协议。

## 登录与同步

```sh
termius login
termius login email -u you@example.com
termius login google
termius status
termius logout
```

命令名、登录参数、交互提示以及状态和退出登录的文字输出均按 Python 源码恢复。
不指定登录方式的 `termius login` 会询问 Google 或邮箱；`login -u 邮箱` 直接选择
邮箱登录。原版的 **`sync` 是 MCP 工具，不是终端子命令**。两个程序都在不加参数
时启动 stdio MCP 服务。

邮箱登录输入 Termius 账号/保险库密码。Google 登录输入 **Termius 保险库加密
密码，不是 Google 密码**。密码输入不回显；SSO 回调和 OTP 使用原版可见输入提示，
不会保存到命令历史。需要双因素认证时终端会提示输入验证码，也可以使用 `--otp`。

Google 流程会给出网页登录地址。完成登录后，不打开 Termius 桌面程序，将
`termius://app/continue-sso?...` 回调粘贴到终端。回调必须匹配本次登录请求，
有效期一小时。网页没有复制按钮时，参考 [Google 回调说明](docs/GOOGLE_SSO.md)。
回调包含登录凭据，不要发送给他人。

默认在加密状态文件中记住保险库密码。`login --no-remember` 保存登录令牌，
同时清除以前记住的密码；后续可向 MCP 进程提供 `TERMIUS_VAULT_PASSWORD`，
或调用 `sync` MCP 工具时传 `password`。该工具的 `remember: false` 表示只在
本次同步使用所提供的密码。

## 功能

| 工具 | 功能 |
| --- | --- |
| `status` | 登录状态、缓存时间、资源数量，不访问网络 |
| `login` | 邮箱/SRP 登录，或发起 Google SSO |
| `login_complete` | 提交 Google 回调、保险库密码和可选 OTP |
| `logout` | 清除本地登录、密码、SSO 状态及资源缓存 |
| `sync` | 主动同步并解密个人/团队资源 |
| `hosts` | 主机列表及大小写不敏感的过滤 |
| `host` | 主机详情、继承后的 SSH 设置、可表达的 SSH 命令 |
| `exec` | SSH 执行，返回标准输出、错误输出及退出码 |
| `files` | SFTP list/stat/read/write/get/put/mkdir/rm/rename |
| `inventory` | 分组、身份、密钥或片段；不返回身份密码和私钥 |

Rust 版使用稳定的 **云端 ID**，可能与 Python 版的本地 ID 不同；请重新查询
`hosts`，不要沿用旧编号。同名主机存在歧义时会报错。`snippets` 会按原版行为
默认返回脚本正文。

`hosts`/`host` 的自动同步间隔为 600 秒；同步失败可以返回旧缓存，并标记
`stale: true` 与 `sync_error`。未登录或缺少密码仍会报错。
`exec`/`files`/`inventory` 默认 60 秒刷新，可由 `TERMIUS_SYNC_TTL` 调整；
同步失败时不会继续执行。缺失、损坏或已撤销的身份/密钥/跳板关系会阻止连接。

### 减少上下文占用

普通返回省略可选云端/密钥接口的技术性警告；例外是账号标记为
`is_team:true` 时，`status`、`sync` 会返回已缓存的团队密钥加载失败提示。
标记为 false 时不显示这条团队提示，包括诊断输出；这只影响展示，
不会跳过共享密钥加载。排障时可调用 MCP `status`，传入
`{"diagnostics":true}` 查看其他已缓存的详细提示。
如果确实存在无法解密的资源，`status`、`sync`、`hosts`、`inventory` 仍返回
大于 0 的 `unreadable_entities` 数量；数量为 0 时省略。已经成功的单主机
SSH/SFTP 操作不再重复全局诊断。实际操作错误和旧缓存提示仍会返回。

以下都是 **MCP 工具的可选参数**，保留终端命令、原版业务字段及默认结果范围：

| 工具 | 参数 | 用途 |
| --- | --- | --- |
| `hosts` | `query`、`limit`、`offset` | 先过滤，再分批返回主机 |
| `inventory` | `limit`、`offset`、`include_script` | 分批返回可见资源；`include_script:false` 省略脚本正文 |
| `files` 的 `action:list` | `limit`、`offset` | 分批返回排序后的目录列表 |
| `exec` | `max_output_chars` | 分别限制 stdout/stderr 保留的字符数；`0` 不保留正文 |

不传分页参数仍返回完整列表。`limit` 范围为 1–10000，`offset` 默认 0，
作用于当前结果集。分页结果增加 `total`、`offset`、`next_offset`，最后一页
的 `next_offset` 为 `null`；`count` 仍表示本次实际返回的条数，不会删除数据。
每页基于当前缓存或目录列表；两次调用之间的云端刷新、目录变更可能改变页内成员。
SFTP 仍保留原来的单目录 10000 项上限。
`include_script` 默认 `true`。`max_output_chars` 范围为 0–200000，默认
200000；有输出被丢弃时返回 `truncated:true` 及简短截断标记，但仍继续读取
SSH 通道直到获得退出状态。大文件 `get`/`put` 只返回元数据，不返回文件正文。

为兼容 MCP 客户端，协议仍同时提供文本 JSON 和 `structuredContent`，符合
[MCP 的兼容建议](https://modelcontextprotocol.io/specification/2025-11-25/server/tools#structured-content)。
客户端是否把两份数据都放进模型上下文，由客户端决定；上述参数能同时缩小两份结果。

### SSH 安全和限制

- 未设置 `strict_host_key_check` 时默认 **false（兼容模式）**，服务器重装或
  更换主机密钥不会因此阻断 SSH/SFTP。此模式不验证服务端身份，无法通过
  指纹变化识别服务器冒充。主机或分组显式设置的 `true` 仍启用严格校验。
- 每个跳板和目标分别遵循自己的继承设置。严格模式优先使用 Termius 登记
  密钥，否则检查用户/系统 `known_hosts`；兼容模式忽略已保存的主机密钥。
  缺失或异常的跳板关系仍会阻止连接，不会回退成直连。
- 当目标和所有跳板都关闭校验时，`exec`/`files` 省略整个
  `host_key_verification`。只要任意一跳启用严格校验，就保留完整的
  `target` 和按连接顺序排列的 `jumps`，取值为 `strict` 或 `disabled`。
  字段省略不代表开启校验；它描述配置模式，不代表握手已完成，
  例如执行超时可能发生在握手之前。
- 严格模式支持普通 SSH 主机公钥、拒绝主机 CA 证书；兼容模式不验证证书信任。
  原生 MCP `exec`/`files` 不转发本地 SSH agent。
- 与 Python 原版一致，`host.agent_forwarding` 读取已保存的账号设置，覆盖
  主机/分组里的同名值；参考 `ssh_command` 同步使用 `ForwardAgent=yes/no`。
  缺少已保存的设置时默认 true。原始云端值按 Python 真值规则转换
  （包括非空字符串），不是 yes/no 字符串解析。这是信息和参考命令的兼容，
  不会开启原生 MCP 连接的 agent 转发。
- 密码、私钥和私钥口令认证已实现。没有显式保险库凭据的直连才尝试本地 agent
  或常见本地私钥。
- `timeout` 范围为 1–86400 秒，默认 60 秒，覆盖 **SSH 连接加执行/传输阶段**。
  之前的自动云端同步单独限制为 120 秒；登录/同步等修改状态的操作串行处理，
  可能排队。客户端工具超时应留出这些时间。
- 执行超时关闭连接，返回 `timed_out: true`、`exit_code: null` 及已捕获输出。
  不能保证远端进程已经停止。MCP 取消会关闭连接链，不再返回该请求结果。
- stdout/stderr 默认分别最多保留 200000 个解码后字符，可通过
  `max_output_chars` 缩小；底层字节缓存也随预算缩小，截断后仍继续读取通道。
- SFTP 内联 read/write 仍限制 200000 字节，因为内容会进入 MCP 消息。
  文件 get/put **不再设置应用层文件总大小上限**，按 32 KiB 分块传输。
  磁盘空间、文件系统和操作超时仍会影响传输；大文件应同时调大 `files.timeout`
  和 MCP 客户端工具超时。本地下载完整成功后才原子替换旧目标；中断远程
  写入可能留下部分内容。
- 目录列表最多 10000 项；递归删除最多 100000 项、深度 128，不跟随目录符号
  链接，并拒绝删除远端文件系统根目录。

## 本地存储

| 环境变量 | 用途 |
| --- | --- |
| `TERMIUS_DATA_DIR` | 覆盖默认的 `~/.termius-rs` 数据目录 |
| `TERMIUS_VAULT_PASSWORD` | 保险库密码，优先于记住的密码 |
| `TERMIUS_SYNC_TTL` | `exec`/`files`/`inventory` 的缓存 TTL 及 `status` 的过期判断，默认 60 秒；`hosts`/`host` 固定 600 秒 |
| `TERMIUS_SECRETS_KEY` | 本地加密口令，请在第一次启动前设置 |
| `TERMIUS_KEYRING` | 1 强制系统钥匙串，0 使用文件密钥；首次默认自动检测 |

本地使用**加密状态文件，不是 SQLite**。`state` 是 JSON 格式的密文封装，将
登录令牌、资源和记住的密码整体加密。密钥来源可以是外部口令、系统
钥匙串或无桌面环境下随机生成的 `state.key`；经 Argon2id 派生后使用
XChaCha20-Poly1305 加密并认证格式、后端及版本号。这是本地格式，与云端
XSalsa20-Poly1305 格式不同。

Unix 上目录须为当前用户所有、权限 0700，文件为 0600，并拒绝状态文件符号
链接和硬链接。Windows 依赖文件 ACL 和系统凭据存储。写入使用原子替换、
文件锁及旧版本冲突检查。CLI 和正在运行的 MCP 会重新读取对方修改；遇到
并发更新错误时重试即可。

MCP 输入或输出连接断开时，会结束会话并取消进行中的操作；输出管道损坏后
不会继续等待输入。

**同时取得 `state` 和 `state.key` 的人可以解密数据。** 需要密钥与目录分离时，
使用外部口令或系统钥匙串。加密不防御已拥有同一系统用户权限的程序。容器
建议从首次启动就配置较强的 `TERMIUS_SECRETS_KEY`，并稳定保存；不要写进
公开配置。

密码错误、文件损坏或钥匙串不可用时会报错并保留原文件；不会静默更换后端。
`logout` 保存空的加密状态，不等于擦除文件系统历史备份。

## 开发验证

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo test --test ssh_openssh --locked -- --ignored
cargo build --release --locked
```

OpenSSH 测试需要 `sshd`/`ssh-keygen`，仅创建临时密钥和 localhost 服务，不修改
现有 SSH 配置或账号密码。`tests/fixtures` 中 Python 文件只用于重新生成独立
开发测试向量，不参与构建和运行。

CI 包含 Linux/macOS/Windows 及最低 Rust 版本检查；具体平台是否通过，以实际
CI 结果为准。安全边界见 [SECURITY.md](SECURITY.md)。

## 许可证

保留上游 [BSD 3-Clause 许可证](LICENSE) 和版权声明，来源说明见 [NOTICE](NOTICE)。
