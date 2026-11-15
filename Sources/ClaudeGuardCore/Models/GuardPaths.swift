import Foundation

/// 统一管理 ClaudeGuard 的所有磁盘路径，支持测试环境注入隔离沙盒目录。
public struct GuardPaths: Sendable, Equatable {
    public let appSupportDir: URL
    public let pendingDir: URL
    public let configFile: URL
    public let stateFile: URL
    public let admissionStateFile: URL
    public let admissionLockFile: URL
    public let eventsFile: URL
    public let pendingHostsBlockFile: URL
    public let pendingPFAnchorFile: URL
    public let pendingIPv6PolicyFile: URL
    public let pendingRequestFile: URL
    public let ipv6BackupFile: URL

    public let systemHelperDir: URL
    public let systemHelperBinary: URL
    public let systemLaunchDaemonPlist: URL
    public let userLaunchAgentPlist: URL
    public let localBinDir: URL

    public init(
        appSupportDir: URL? = nil,
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser,
        systemRoot: URL = URL(fileURLWithPath: "/")
    ) {
        let base: URL
        if let explicit = appSupportDir {
            base = explicit
        } else if let envOverride = ProcessInfo.processInfo.environment["CLAUDEGUARD_DATA_DIR"], !envOverride.isEmpty {
            base = URL(fileURLWithPath: envOverride)
        } else {
            base = homeDirectory
                .appendingPathComponent("Library", isDirectory: true)
                .appendingPathComponent("Application Support", isDirectory: true)
                .appendingPathComponent("ClaudeGuard", isDirectory: true)
        }

        let pending = base.appendingPathComponent("pending", isDirectory: true)
        self.appSupportDir = base
        self.pendingDir = pending
        self.configFile = base.appendingPathComponent("config.json")
        self.stateFile = base.appendingPathComponent("state.json")
        self.admissionStateFile = base.appendingPathComponent("admission-state.json")
        self.admissionLockFile = base.appendingPathComponent("admission-state.lock")
        self.eventsFile = base.appendingPathComponent("events.jsonl")
        self.pendingHostsBlockFile = pending.appendingPathComponent("hosts.block")
        self.pendingPFAnchorFile = pending.appendingPathComponent("pf.anchor")
        self.pendingIPv6PolicyFile = pending.appendingPathComponent("ipv6.policy")
        self.pendingRequestFile = pending.appendingPathComponent("request")
        self.ipv6BackupFile = base.appendingPathComponent("ipv6-backup.json")

        let sysSupport = systemRoot
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("ClaudeGuard", isDirectory: true)
        self.systemHelperDir = sysSupport
        self.systemHelperBinary = sysSupport.appendingPathComponent("claudeguard-helper")
        self.systemLaunchDaemonPlist = systemRoot
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("LaunchDaemons", isDirectory: true)
            .appendingPathComponent("com.claudeguard.helper.plist")
        self.userLaunchAgentPlist = homeDirectory
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("LaunchAgents", isDirectory: true)
            .appendingPathComponent("com.claudeguard.agent.plist")
        self.localBinDir = homeDirectory
            .appendingPathComponent(".local", isDirectory: true)
            .appendingPathComponent("bin", isDirectory: true)
    }

    public static let live = GuardPaths()

    public func ensureDirectoriesExist() throws {
        let fm = FileManager.default
        try fm.createDirectory(at: appSupportDir, withIntermediateDirectories: true)
        try fm.createDirectory(
            at: pendingDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: pendingDir.path)
    }
}
