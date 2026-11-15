# 🛡️ ClaudeGuard for macOS

**基于 `Swift 6 + SwiftUI + C LaunchDaemon` 构建的 macOS 原生多 AI 客户端网络出口门禁。**

防止在忘记开启 `v2rayN`（如前一天关闭代理、次日直接点击 Dock 栏启动）、代理节点意外掉线、UDP 直连漏网或分流规则写漏时，**Claude Desktop（含内置 Claude Code）**、**ChatGPT / Codex**、**Cursor**、**Antigravity** 等客户端带着本机真实 IP 发出请求触发账号风控。

---

## 核心特性

1. **零终端记忆成本 · 全原生图形化交互**
   - **现代悬浮控制卡片（`MenuBarExtra(.window)`）**：点击菜单栏盾牌直观查看当前出口 IP、国家码、节点备注、多路探测耗时及 `v2rayN` / `TUN` 状态；支持一键将当前节点加入白名单。
   - **独立原生设置窗口（`⌘,`）**：四标签可视化管理带备注名的 IP/CIDR 白名单、允许国家/地区码、受保护客户端列表（支持从 `/Applications` 添加任意自定义 `.app`）与实时拦截时间线。
   - **图形化安装与无残留卸载**：首次打开通过内置向导一键唤起 macOS 系统密码弹窗部署底层特权服务；设置页提供「紧急解封网络」与「彻底卸载并还原」按钮，无需保留或记忆任何脚本命令。

2. **内核级零泄漏双防线 + `v2rayN` 联动**
   - **第一道防线（代理断开瞬间提前锁死网络）**：监听 `SCDynamicStore` 路由/代理变更、`NWPathMonitor` 与合盖唤醒事件；一旦出口偏离白名单，特权助手立即将目标域名写入 `/etc/hosts` 沉洞，并在 macOS 原生 `pf` 子锚点 `com.apple/claudeguard` 中下发 `block drop out quick proto { tcp, udp }`（阻断 HTTP/3 QUIC 与已有长连接，同时不破坏 AirDrop、系统防火墙或 `v2rayN` 自身的代理隧道）。
   - **第二道防线（Dock 启动毫秒级拦截）**：通过 `NSWorkspace.didLaunchApplicationNotification` 监听桌面端启动，未通过白名单时毫秒级终止启动并弹出提示；若检测到本机 `v2rayN.app` 未运行，弹窗直接提供 **「启动 v2rayN」** 按钮。

3. **融合三路出口一致性校验（堵死分流盲区）**
   - 并行校验 **通用 HTTP 出口** + **UDP STUN 出口（RFC 5389）** + **各目标真实链路（`claude.ai/cdn-cgi/trace`、`chatgpt.com/cdn-cgi/trace` 等）**。
   - 支持 **固定 IP / CIDR 白名单（IPv4 & IPv6，每条可独立备注与启停）**、**ISO 二位国家/地区码**、以及 **持久化 IP 跳变锁**（出口跳变到其他白名单节点也会锁死，直至手动确认信任）。

4. **进程级时区自动对齐（不修改 Mac 系统时区）**
   - 根据当前代理出口的 `loc` 国家码与 Cloudflare `colo` 边缘机房代码，自动推导自洽的当地 IANA 时区（如 `KR` → `Asia/Seoul`、`US + LAX` → `America/Los_Angeles`、`US + EWR` → `America/New_York`，也支持手动指定固定时区）。
   - 同时作用于**桌面端应用**（支持从菜单栏一键带时区启动，或直接点 Dock 图标时自动通过 LaunchServices 无损注入 `TZ` 重拉起）与**终端 `claude` CLI 会话**，整台 Mac 的系统时间、日历与微信保持北京时间不变。

5. **Claude 专属全链路覆盖**
   - 同时覆盖 `Claude.app`（`com.anthropic.claudefordesktop`）、桌面端内嵌的 `Claude-3p/.../claude.app`（`com.anthropic.claude-code`）以及终端独立安装的 `claude` CLI（原生编译薄包装器启动开销 < 5ms，60 秒自愈巡检防更新覆盖）。
   - 支持一键**禁止 Claude 自动更新**（`ShipIt` 目录 `uchg` 锁定 + 更新域名屏蔽 + CLI 环境变量注入）。

---

## 快速构建与安装

环境要求：macOS 14.0+，已安装 Xcode 或 Xcode Command Line Tools（本机编译 + Ad-hoc 签名，无 Gatekeeper 拦截，无需付费 Apple Developer 账号）。

### 1. 一键编译并打包 `ClaudeGuard.app`

```bash
./scripts/build-app.sh
```

构建完成后产物位于 `dist/ClaudeGuard.app`。

### 2. 移入「应用程序」并启动

```bash
cp -R dist/ClaudeGuard.app /Applications/
```

```bash
open /Applications/ClaudeGuard.app
```

首次打开会自动弹出 **「ClaudeGuard 初始防线配置」** 向导窗口：
1. 点击 **「授权安装特权网络助手…」** 输入一次 Mac 登录密码；
2. 确认 `v2rayN`（推荐开启 **TUN 模式**）已连接，核对检测到的代理出口 IP，填写备注并点击 **「加入白名单」** → **「立即开启守护」** 即可。

---

## 工程结构与开发测试

```text
├── Package.swift                        # Swift 6 多 Target 工程定义
├── scripts/
│   ├── build-app.sh                     # 编译打包并签名 dist/ClaudeGuard.app
│   └── generate-icon.swift              # CoreGraphics 原生图标生成器
├── Sources/
│   ├── ClaudeGuardCore/                 # 核心探测、CIDR 匹配、策略判定与执行器库
│   ├── ClaudeGuardApp/                  # SwiftUI 菜单栏卡片、四标签设置窗口与向导
│   ├── ClaudeGuardCLI/                  # 原生极速 claude 命令行包装器与辅助诊断工具
│   └── ClaudeGuardHelper/               # C 语言 Root LaunchDaemon 特权助手 (hosts_helper.c)
└── Tests/
    └── ClaudeGuardCoreTests/            # 核心逻辑单元测试套件
```

运行单元测试：

```bash
swift test
```

只读实测当前网络三路探测（不修改任何系统配置）：

```bash
./dist/ClaudeGuard.app/Contents/Helpers/claudeguard-cli status --dry-run
```
