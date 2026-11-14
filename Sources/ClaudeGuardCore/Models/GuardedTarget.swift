import Foundation

/// 单个被守护的 AI 客户端目标配置（内置预设或用户自定义应用）。
public struct GuardedTarget: Codable, Sendable, Equatable, Identifiable {
    public var id: String
    public var name: String
    public var subtitle: String
    public var isBuiltIn: Bool
    public var isEnabled: Bool
    /// 匹配的 Bundle ID 精确值或前缀（例如 `com.anthropic.claude`、`com.openai.`）
    public var bundleIDPrefixes: [String]
    /// 兜底应用名或可执行路径特征（用于子进程清理）
    public var processPathKeywords: [String]
    /// 默认安装路径（用于检测本机是否安装、读取图标）
    public var defaultAppPaths: [String]
    /// 真实链路出口探测 URL（如 `https://claude.ai/cdn-cgi/trace`）
    public var traceURL: String?
    /// 需要通过 `/etc/hosts` 沉洞封禁的根域名（自动展开常用子域名前缀）
    public var blockedApexDomains: [String]
    /// 需要额外精确封禁的完整域名
    public var blockedExactDomains: [String]
    /// 允许进入内核 `pf` 阻断表的官方专属网段（避免将共享 Cloudflare CDN IP 写入 pf 误伤其他网站）
    public var dedicatedPFCIDRs: [String]
    /// 用于通过外部 DNS 解析进入 `pf` 阻断表的核心域名
    public var pfResolveDomains: [String]
    /// 当外部 DNS 不可达时兜底写入 `pf` 表的官方固定 IP
    public var pfFallbackIPs: [String]

    public init(
        id: String,
        name: String,
        subtitle: String,
        isBuiltIn: Bool = false,
        isEnabled: Bool = true,
        bundleIDPrefixes: [String],
        processPathKeywords: [String],
        defaultAppPaths: [String],
        traceURL: String?,
        blockedApexDomains: [String],
        blockedExactDomains: [String] = [],
        dedicatedPFCIDRs: [String] = [],
        pfResolveDomains: [String] = [],
        pfFallbackIPs: [String] = []
    ) {
        self.id = id
        self.name = name
        self.subtitle = subtitle
        self.isBuiltIn = isBuiltIn
        self.isEnabled = isEnabled
        self.bundleIDPrefixes = bundleIDPrefixes
        self.processPathKeywords = processPathKeywords
        self.defaultAppPaths = defaultAppPaths
        self.traceURL = traceURL
        self.blockedApexDomains = blockedApexDomains
        self.blockedExactDomains = blockedExactDomains
        self.dedicatedPFCIDRs = dedicatedPFCIDRs
        self.pfResolveDomains = pfResolveDomains
        self.pfFallbackIPs = pfFallbackIPs
    }

    public static let commonSubdomainPrefixes: [String] = [
        "", "www", "app", "api", "auth", "stats", "cdn", "assets",
        "console", "docs", "support", "feedback", "desktop-app-updates",
        "a-api", "a-cdn", "code", "status", "blog", "research", "events",
        "login", "register", "portal", "admin", "v1", "v2", "v3",
        "ws", "gateway", "proxy", "assets-proxy", "account", "settings", "billing", "ab"
    ]

    /// 展开当前目标应写入 `/etc/hosts` 的全部域名集合。
    public var expandedBlockedDomains: Set<String> {
        var result = Set(blockedExactDomains.map { $0.lowercased() })
        for apex in blockedApexDomains {
            let cleanApex = apex.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard !cleanApex.isEmpty else { continue }
            result.insert(cleanApex)
            for prefix in Self.commonSubdomainPrefixes where !prefix.isEmpty {
                result.insert("\(prefix).\(cleanApex)")
            }
        }
        return result
    }

    // MARK: - 内置四大 AI 客户端预设

    public static let claudePreset = GuardedTarget(
        id: "claude",
        name: "Claude (Desktop + Claude Code)",
        subtitle: "守护 Claude.app、内嵌 Claude Code 引擎、独立 claude CLI 及 Anthropic 全系域名",
        isBuiltIn: true,
        isEnabled: true,
        bundleIDPrefixes: [
            "com.anthropic.claudefordesktop",
            "com.anthropic.claudefor-mac",
            "com.anthropic.claude-code",
            "com.anthropic.claude"
        ],
        processPathKeywords: [
            "/Claude.app/Contents/",
            "/claude-code/",
            "/claude.app/Contents/MacOS/claude"
        ],
        defaultAppPaths: [
            "/Applications/Claude.app"
        ],
        traceURL: "https://claude.ai/cdn-cgi/trace",
        blockedApexDomains: [
            "claude.ai",
            "claude.com",
            "claude.usercontent.com",
            "anthropic.com",
            "anthropic.ai"
        ],
        blockedExactDomains: [
            "desktop-app-updates.anthropic.com",
            "statsig.anthropic.com"
        ],
        dedicatedPFCIDRs: [
            "160.79.104.0/24",
            "2607:6bc0::/32"
        ],
        pfResolveDomains: [
            "claude.ai", "www.claude.ai", "app.claude.ai", "api.claude.ai", "auth.claude.ai",
            "claude.com", "www.claude.com", "app.claude.com", "api.claude.com", "console.claude.com",
            "anthropic.com", "api.anthropic.com", "console.anthropic.com"
        ],
        pfFallbackIPs: [
            "160.79.104.10",
            "2607:6bc0::10"
        ]
    )

    public static let chatgptPreset = GuardedTarget(
        id: "chatgpt",
        name: "ChatGPT / Codex",
        subtitle: "守护 ChatGPT.app（含 Codex 桌面端）及 OpenAI 核心域名",
        isBuiltIn: true,
        isEnabled: false,
        bundleIDPrefixes: [
            "com.openai.chat",
            "com.openai.codex",
            "com.openai."
        ],
        processPathKeywords: [
            "/ChatGPT.app/Contents/",
            "/Codex.app/Contents/"
        ],
        defaultAppPaths: [
            "/Applications/ChatGPT.app",
            "/Applications/Codex.app"
        ],
        traceURL: "https://chatgpt.com/cdn-cgi/trace",
        blockedApexDomains: [
            "chatgpt.com",
            "openai.com",
            "oaistatic.com",
            "oaiusercontent.com"
        ],
        blockedExactDomains: [
            "ab.chatgpt.com",
            "ws.chatgpt.com",
            "ios.chat.openai.com"
        ]
    )

    public static let cursorPreset = GuardedTarget(
        id: "cursor",
        name: "Cursor",
        subtitle: "守护 Cursor AI 编辑器及 cursor.com / cursor.sh 后端连接",
        isBuiltIn: true,
        isEnabled: false,
        bundleIDPrefixes: [
            "com.todesktop.230313mzl4w4u92",
            "com.cursor.Cursor"
        ],
        processPathKeywords: [
            "/Cursor.app/Contents/"
        ],
        defaultAppPaths: [
            "/Applications/Cursor.app"
        ],
        traceURL: "https://www.cursor.com/cdn-cgi/trace",
        blockedApexDomains: [
            "cursor.com",
            "cursor.sh"
        ],
        blockedExactDomains: [
            "api2.cursor.sh",
            "api3.cursor.sh",
            "repo42.cursor.sh",
            "marketplace.cursorapi.com"
        ]
    )

    public static let antigravityPreset = GuardedTarget(
        id: "antigravity",
        name: "Antigravity / Gemini",
        subtitle: "守护 Antigravity 客户端及 Google AI Studio / Cloud Code 域名",
        isBuiltIn: true,
        isEnabled: false,
        bundleIDPrefixes: [
            "com.google.antigravity",
            "com.antigravity."
        ],
        processPathKeywords: [
            "/Antigravity.app/Contents/"
        ],
        defaultAppPaths: [
            "/Applications/Antigravity.app"
        ],
        traceURL: nil,
        blockedApexDomains: [
            "antigravity.google"
        ],
        blockedExactDomains: [
            "cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
            "aistudio.google.com",
            "gemini.google.com"
        ]
    )

    public static let defaultTargets: [GuardedTarget] = [
        .claudePreset,
        .chatgptPreset,
        .cursorPreset,
        .antigravityPreset
    ]
}
