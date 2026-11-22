# guest-bridge (`guestctl`)

[English](./README.md) | **简体中文**

**零第三方依赖、纯 Go 标准库实现、端到端加密的交互式临时远程协助与联调工具。**

`guest-bridge` 用于让协助者在自己电脑（或本地 AI 编程助手）上协助排查另一台 **Linux（x86_64 / ARM64）** 或 **Windows（x64）** 机器的问题，**无需在目标机安装 SSH 服务、不在目标机落地协助者的任何账号与凭据，并把实时可见性与操作审批权牢牢交在目标机所有者手中。**

---

## 核心特性

- **零第三方依赖**：100% 使用 Go 标准库编写（`go.mod` 无任何外部模块），代码精简、透明，几分钟即可完整审计。
- **联网前强制本地授权菜单**：`guest-agent` 启动后必须检测交互式控制台，**在建立中继隧道之前**先由目标机所有者亲手选择本次权限：
  - **`[1]` 纯只读诊断**：仅允许查看文件、列目录、搜索与系统概览；彻底禁用一切文件写入与通用命令执行。
  - **`[2]` 自由只读排查 + 逐次审批写入**：系统可信路径下的只读查询自动运行并实时打印透明日志；读取敏感凭证路径（`~/.ssh`、`.env`、`*.key`/`*.pem`、`/etc/shadow`、`/proc/*/environ`）、所有文件修改（先展示红绿彩色 Diff）、修改类/复合命令及截屏均强制弹 `[y/N]` 确认；拒绝修改时不回传任何文件内容或 Diff。
  - **`[3]` 仅限当前目录模式**：将文件操作严格锁定在启动时的当前目录内（含规范路径与符号链接逃逸检查），彻底禁用通用 Shell 命令，写入同样需 `[y/N]` 确认。
  - **`[q]` 取消退出**：不建立任何网络连接，立即退出。
- **退出屏幕操作摘要**：按 `Ctrl+C` 或由主控端执行 `guestctl close` 后，立即断开通道、尽力清理临时二进制，并在目标机屏幕打印本次会话摘要（读过的文件、只读查询次数、批准的命令/修改/截屏、已拒绝次数），**不在目标机写日志文件**。
- **端到端加密盲转发**：隧道使用 TLS 1.3 证书指纹固定 + 双向 HMAC 认证握手 + AES-256-GCM 递增序号帧加密；中继不接收 256 位端到端密钥（PSK），不落盘任何会话日志。
- **公开 Release 透明分发 + 独立校验**：支持优先从 GitHub Releases 官方构建直连拉取（可选国内/私有中继镜像兜底），并在执行前对照主控端本地固化的 `SHA-256` 校验。
- **归档仅留存主控端本地**：会话元数据（`meta.json`）、审计日志（`session.jsonl`）、修改前备份与 Diff（`diffs/`）、桌面截图（`screenshots/`）仅保存在主控机 `~/.local/share/guestctl/sessions/`。*（注：连接建立后，目标机将上报用户名、主机名、系统版本与启动目录供排查使用。）*

---

## 整体架构

```text
主控端 (guestctl)                             目标机 (guest-agent)
  ├─ 本地 CLI 与后台守护 (0600 Unix Socket)     ├─ 联网前本地 [1/2/3/q] 权限选择菜单
  ├─ 本机随机生成 256 位 E2EE 密钥 (PSK)        ├─ 实时打印只读日志 + [y/N] 彩色 Diff 门禁
  └─ 日志/Diff/备份/截图仅归档于本机             └─ 退出打印屏幕操作摘要并尽力清理临时文件
               │                                               │
               └────────── TLS 1.3（证书指纹固定）─────────────┘
                                      │
                        自建盲转发中继 (guest-relay)
                   非 root 专用用户 · 0600 私有 admin.sock
                         纯密文转发 · 零业务落盘
```

---

## 快速开始

### 1. 编译静态二进制（或直接下载 Releases）

需要 Go 1.24+：

```bash
chmod +x scripts/build.sh
./scripts/build.sh
install -m 0755 dist/guestctl ~/.local/bin/guestctl
```

`scripts/build.sh` 会在 `dist/` 生成静态 `CGO_ENABLED=0` 可执行文件：
- `guest-relay`（Linux x86_64）
- `guestctl`（Linux x86_64）
- `guest-agent-linux-amd64`
- `guest-agent-linux-arm64`（Jetson / 树莓派 / Termux）
- `guest-agent-windows-amd64.exe`（Windows 10 / 11，投入生产前建议在目标 PowerShell 实机验证）

同时会在本机 `~/.local/share/guestctl/agent-*.sha256` 写入独立校验摘要，避免盲信中继自报哈希。

### 2. 在中继服务器部署 `guest-relay`

将 `dist/guest-relay` 安装到 `/usr/local/bin/guest-relay`，将 `guest-agent-*` 放到 `/var/lib/guest-relay/bin/`（归属 `root:root`，对中继进程只读），创建无登录专用账号 `guest-relay`，并通过 systemd 运行：

```ini
[Unit]
Description=Hardened E2EE Guest Bridge Relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=guest-relay
Group=guest-relay
RuntimeDirectory=guest-relay
RuntimeDirectoryMode=0750
ExecStart=/usr/local/bin/guest-relay \
  -addr=:34434 \
  -admin-sock=/run/guest-relay/admin.sock \
  -ip=YOUR_RELAY_PUBLIC_IP \
  -data=/var/lib/guest-relay \
  -ttl=10m
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=/var/lib/guest-relay /run/guest-relay
ReadOnlyPaths=/var/lib/guest-relay/bin

[Install]
WantedBy=multi-user.target
```

在中继防火墙放行 `TCP 34434` 端口即可。管理接口仅监听于 `0600` 权限的 `/run/guest-relay/admin.sock`，不对外暴露管理端口。

### 3. 在主控端配置 `guestctl`

创建 `~/.config/guestctl/config.json` 并设为 `0600` 权限：

```bash
mkdir -p ~/.config/guestctl && chmod 700 ~/.config/guestctl
cat > ~/.config/guestctl/config.json << 'EOF'
{
  "ssh_host": "my-relay-ssh-alias",
  "relay_addr": "YOUR_RELAY_IP_OR_DOMAIN:34434",
  "admin_sock": "/run/guest-relay/admin.sock",
  "admin_user": "guest-relay",
  "release_url": "https://github.com/LHzeromy/guest-bridge/releases/download/v0.1.1"
}
EOF
chmod 600 ~/.config/guestctl/config.json
```

> 若希望目标机拉取 GitHub Releases 官方构建并校验一致，请从 Releases 下载对应版本的二进制及 `SHA256SUMS.txt` 同步至中继 `/var/lib/guest-relay/bin/` 和本机 `~/.local/share/guestctl/agent-*.sha256`。

### 4. 配对与交互排查

```bash
# 1. 在主控端本地终端生成一次性配对命令（请勿将含密钥的配对命令贴进云端聊天）
guestctl pair                       # 默认 Linux x86_64（优先 GitHub，失败自动回退中继镜像）
guestctl pair --from github         # 仅从 GitHub Releases 下载（纯 CA 校验 HTTPS，无 -k）
guestctl pair --os win              # Windows 10/11 PowerShell 脚本块
guestctl pair --os arm64            # Linux ARM64

# 2. 目标机所有者粘贴执行，在本地 [1/2/3/q] 菜单中亲手选择授予的权限

# 3. 主控端开始排查与修复
guestctl status
guestctl sysinfo
guestctl ls --depth 2 /path/to/project
guestctl read --start 1 --end 120 /path/to/file
guestctl grep "ERROR" /path/to/logs
guestctl exec "nvidia-smi"
guestctl edit --old "batch_size = 64" --new "batch_size = 16" /path/to/train.py
guestctl screenshot

# 4. 结束会话（目标机按 Ctrl+C 或主控端执行 close 均可随时断开）
guestctl close
```

---

## 安全说明与许可证

- 详细威胁模型与安全边界见 [SECURITY.md](./SECURITY.md)
- 开源协议：[MIT License](./LICENSE)
