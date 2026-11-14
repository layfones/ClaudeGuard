import Foundation

/// 自动发现本机独立安装的 `claude` CLI 二进制（严格排除我们自己的 `claudeguard-cli` 包装器以防递归 fork 炸弹），
/// 并在 `~/.local/bin/claude` 等目录维护软链钩子与 60 秒自愈修复。
public enum CLIHookManager {
    public struct StatusReport: Sendable, Equatable {
        public var realCLIPath: String?
        public var wrapperBinaryPath: String?
        public var hookedLocations: [String]
        public var notes: [String]

        public init(
            realCLIPath: String? = nil,
            wrapperBinaryPath: String? = nil,
            hookedLocations: [String] = [],
            notes: [String] = []
        ) {
            self.realCLIPath = realCLIPath
            self.wrapperBinaryPath = wrapperBinaryPath
            self.hookedLocations = hookedLocations
            self.notes = notes
        }
    }

    /// 定位当前应用内置或同目录构建出的 `claudeguard-cli` 原生可执行文件。
    public static func locateWrapperBinary() -> String? {
        let fm = FileManager.default
        // 1. 若从 ClaudeGuard.app 运行：Contents/Helpers/claudeguard-cli 或 Contents/MacOS/claudeguard-cli
        let bundleURL = Bundle.main.bundleURL
        let candidatesFromBundle = [
            bundleURL.appendingPathComponent("Contents/Helpers/claudeguard-cli").path,
            bundleURL.appendingPathComponent("Contents/MacOS/claudeguard-cli").path
        ]
        for c in candidatesFromBundle where fm.isExecutableFile(atPath: c) {
            return c
        }

        // 2. 若自身就是 claudeguard-cli 或在同一构建目录下
        if let execPath = Bundle.main.executablePath {
            let resolved = URL(fileURLWithPath: execPath).resolvingSymlinksInPath().path
            if resolved.hasSuffix("/claudeguard-cli") && fm.isExecutableFile(atPath: resolved) {
                return resolved
            }
            let sibling = URL(fileURLWithPath: resolved)
                .deletingLastPathComponent()
                .appendingPathComponent("claudeguard-cli")
                .path
            if fm.isExecutableFile(atPath: sibling) {
                return sibling
            }
        }

        // 3. 默认安装位置 /Applications/ClaudeGuard.app
        let defaultInstalled = "/Applications/ClaudeGuard.app/Contents/Helpers/claudeguard-cli"
        if fm.isExecutableFile(atPath: defaultInstalled) {
            return defaultInstalled
        }
        return nil
    }

    /// 判断给定路径是否指向 ClaudeGuard 自身的包装器（严防包装器调用包装器造成死循环）。
    public static func isOurWrapper(_ path: String) -> Bool {
        guard !path.isEmpty else { return false }
        let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        let base = (resolved as NSString).lastPathComponent
        if base == "claudeguard-cli" || base == "ClaudeGuard" || resolved.contains("ClaudeGuard.app") {
            return true
        }
        return false
    }

    /// 搜索本机真实的独立 `claude` CLI 二进制路径。
    public static func discoverRealCLI(
        configuredPath: String?,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> String? {
        let fm = FileManager.default
        var candidates: [String] = []

        if let explicit = configuredPath, !explicit.isEmpty {
            candidates.append(explicit)
        }

        // Homebrew Caskroom 最新版本优先
        for caskRoot in ["/opt/homebrew/Caskroom/claude-code", "/usr/local/Caskroom/claude-code"] {
            if let versions = try? fm.contentsOfDirectory(atPath: caskRoot).sorted().reversed() {
                for ver in versions {
                    candidates.append("\(caskRoot)/\(ver)/claude")
                }
            }
        }

        // 官方原生安装器目录 `~/.local/share/claude/versions/*` 与 npm/bun/volta 目录
        let versionsDir = homeDirectory.appendingPathComponent(".local/share/claude/versions").path
        if let versions = try? fm.contentsOfDirectory(atPath: versionsDir).sorted().reversed() {
            for ver in versions {
                candidates.append("\(versionsDir)/\(ver)")
                candidates.append("\(versionsDir)/\(ver)/claude")
            }
        }

        let home = homeDirectory.path
        candidates.append(contentsOf: [
            "\(home)/.claude/local/claude",
            "\(home)/.claude/local/node_modules/.bin/claude",
            "\(home)/.bun/bin/claude",
            "\(home)/.volta/bin/claude",
            "/opt/homebrew/bin/claude",
            "/usr/local/bin/claude",
            "\(home)/.local/bin/claude"
        ])

        for candidate in candidates {
            let resolved = URL(fileURLWithPath: candidate).resolvingSymlinksInPath().path
            guard fm.isExecutableFile(atPath: resolved) else { continue }
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: resolved, isDirectory: &isDir), !isDir.boolValue else { continue }
            if !isOurWrapper(resolved) {
                return resolved
            }
        }
        return nil
    }

    /// 挂载或修复 `claudeguard` 管理命令软链，并在 `protectCLI == true` 且存在真实 `claude` 时挂载 `claude` 软链。
    @discardableResult
    public static func syncHooks(
        protectCLI: Bool,
        configuredRealCLI: String?,
        paths: GuardPaths = .live
    ) -> StatusReport {
        let fm = FileManager.default
        let wrapper = locateWrapperBinary()
        let realCLI = discoverRealCLI(configuredPath: configuredRealCLI)
        var hooked: [String] = []
        var notes: [String] = []

        guard let wrapperPath = wrapper else {
            return StatusReport(
                realCLIPath: realCLI,
                wrapperBinaryPath: nil,
                hookedLocations: [],
                notes: ["尚未定位到 claudeguard-cli 二进制"]
            )
        }

        try? fm.createDirectory(at: paths.localBinDir, withIntermediateDirectories: true)

        // 始终挂载 ~/.local/bin/claudeguard 方便终端急救查看状态
        let mgmtLink = paths.localBinDir.appendingPathComponent("claudeguard").path
        if replaceSymlinkAtomically(at: mgmtLink, destination: wrapperPath, allowCreateNew: true) {
            hooked.append(mgmtLink)
        }

        if !protectCLI {
            unhookClaudeCommand(realCLIPath: realCLI, paths: paths)
            notes.append("CLI 命令行拦截已关闭")
            return StatusReport(realCLIPath: realCLI, wrapperBinaryPath: wrapperPath, hookedLocations: hooked, notes: notes)
        }

        guard let real = realCLI else {
            notes.append("本机暂未安装独立的 claude 命令行（Claude Desktop 内嵌的 Code 会话已由桌面进程防线直接保护）")
            return StatusReport(realCLIPath: nil, wrapperBinaryPath: wrapperPath, hookedLocations: hooked, notes: notes)
        }

        let primaryClaudeLink = paths.localBinDir.appendingPathComponent("claude").path
        if replaceSymlinkAtomically(at: primaryClaudeLink, destination: wrapperPath, allowCreateNew: true) {
            hooked.append(primaryClaudeLink)
        }

        for dir in ["/opt/homebrew/bin", "/usr/local/bin"] {
            let linkPath = "\(dir)/claude"
            // 仅当该目录已有软链且可写时替换，绝不覆盖真实二进制实体文件
            if isSymlink(at: linkPath) && fm.isWritableFile(atPath: dir) {
                if replaceSymlinkAtomically(at: linkPath, destination: wrapperPath, allowCreateNew: false) {
                    hooked.append(linkPath)
                }
            }
        }

        let _ = real
        return StatusReport(realCLIPath: realCLI, wrapperBinaryPath: wrapperPath, hookedLocations: hooked, notes: notes)
    }

    /// 卸载或关闭 CLI 守护时还原软链。
    public static func unhookClaudeCommand(realCLIPath: String?, paths: GuardPaths = .live) {
        let fm = FileManager.default
        let candidates = [
            paths.localBinDir.appendingPathComponent("claude").path,
            "/opt/homebrew/bin/claude",
            "/usr/local/bin/claude"
        ]
        for link in candidates where isSymlink(at: link) {
            guard let dest = try? fm.destinationOfSymbolicLink(atPath: link) else { continue }
            let resolved = URL(fileURLWithPath: dest, relativeTo: URL(fileURLWithPath: link).deletingLastPathComponent())
                .resolvingSymlinksInPath().path
            if isOurWrapper(resolved) {
                try? fm.removeItem(atPath: link)
                if let real = realCLIPath, fm.isExecutableFile(atPath: real) {
                    try? fm.createSymbolicLink(atPath: link, withDestinationPath: real)
                }
            }
        }
    }

    public static func removeAllLinks(configuredRealCLI: String?, paths: GuardPaths = .live) {
        let real = discoverRealCLI(configuredPath: configuredRealCLI)
        unhookClaudeCommand(realCLIPath: real, paths: paths)
        let mgmtLink = paths.localBinDir.appendingPathComponent("claudeguard").path
        if isSymlink(at: mgmtLink) {
            try? FileManager.default.removeItem(atPath: mgmtLink)
        }
    }

    private static func isSymlink(at path: String) -> Bool {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let type = attrs[.type] as? FileAttributeType else {
            return false
        }
        return type == .typeSymbolicLink
    }

    private static func replaceSymlinkAtomically(
        at linkPath: String,
        destination: String,
        allowCreateNew: Bool
    ) -> Bool {
        let fm = FileManager.default
        if fm.fileExists(atPath: linkPath) || isSymlink(at: linkPath) {
            // 绝不覆盖非软链的常规二进制文件
            guard isSymlink(at: linkPath) else { return false }
            if let currentDest = try? fm.destinationOfSymbolicLink(atPath: linkPath),
               currentDest == destination {
                return true
            }
        } else if !allowCreateNew {
            return false
        }

        let tmpLink = linkPath + ".claudeguard.tmp.\(ProcessInfo.processInfo.processIdentifier)"
        try? fm.removeItem(atPath: tmpLink)
        do {
            try fm.createSymbolicLink(atPath: tmpLink, withDestinationPath: destination)
            if rename(tmpLink, linkPath) != 0 {
                try? fm.removeItem(atPath: tmpLink)
                return false
            }
            return true
        } catch {
            try? fm.removeItem(atPath: tmpLink)
            return false
        }
    }
}
