import Foundation

/// 图形化安装/升级/卸载底层 Root LaunchDaemon 特权助手与开机登录项（直接唤起 macOS 原生密码授权弹窗，零终端操作）。
public enum PrivilegedInstaller {
    public static let helperLabel = "com.claudeguard.helper"
    public static let agentLabel = "com.claudeguard.agent"

    public static func isHelperInstalled(paths: GuardPaths = .live) -> Bool {
        let fm = FileManager.default
        return fm.isExecutableFile(atPath: paths.systemHelperBinary.path)
            && fm.fileExists(atPath: paths.systemLaunchDaemonPlist.path)
    }

    /// 定位待安装的编译版 `claudeguard-helper` C 二进制。
    public static func locateBundledHelperBinary() -> String? {
        let fm = FileManager.default
        let bundleURL = Bundle.main.bundleURL
        let candidates = [
            bundleURL.appendingPathComponent("Contents/Helpers/claudeguard-helper").path,
            bundleURL.appendingPathComponent("Contents/MacOS/claudeguard-helper").path
        ]
        for c in candidates where fm.isExecutableFile(atPath: c) {
            return c
        }
        if let execPath = Bundle.main.executablePath {
            let sibling = URL(fileURLWithPath: execPath)
                .resolvingSymlinksInPath()
                .deletingLastPathComponent()
                .appendingPathComponent("claudeguard-helper")
                .path
            if fm.isExecutableFile(atPath: sibling) {
                return sibling
            }
        }
        return nil
    }

    /// 生成 `/Library/LaunchDaemons/com.claudeguard.helper.plist` 内容。
    public static func buildHelperLaunchDaemonPlist(paths: GuardPaths = .live) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(helperLabel)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(paths.systemHelperBinary.path)</string>
                <string>\(paths.appSupportDir.path)</string>
            </array>
            <key>WatchPaths</key>
            <array>
                <string>\(paths.pendingRequestFile.path)</string>
            </array>
            <key>StandardOutPath</key>
            <string>/tmp/claudeguard-helper.log</string>
            <key>StandardErrorPath</key>
            <string>/tmp/claudeguard-helper.err</string>
        </dict>
        </plist>
        """
    }

    /// 唤起 macOS 原生管理员密码弹窗，一步部署 Root LaunchDaemon 特权网络助手。
    public static func installPrivilegedHelper(paths: GuardPaths = .live) throws {
        guard let sourceHelper = locateBundledHelperBinary() else {
            throw NSError(
                domain: "ClaudeGuard.Installer",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "未找到内置的 claudeguard-helper 二进制，请使用构建脚本打包完整应用。"]
            )
        }

        try paths.ensureDirectoriesExist()
        if !FileManager.default.fileExists(atPath: paths.pendingRequestFile.path) {
            FileManager.default.createFile(
                atPath: paths.pendingRequestFile.path,
                contents: Data("init\n".utf8),
                attributes: [.posixPermissions: 0o600]
            )
        }

        let tempPlist = paths.appSupportDir.appendingPathComponent("com.claudeguard.helper.plist.stage")
        let plistContent = buildHelperLaunchDaemonPlist(paths: paths)
        try Data(plistContent.utf8).write(to: tempPlist, options: .atomic)
        defer { try? FileManager.default.removeItem(at: tempPlist) }

        let sysDir = shellQuote(paths.systemHelperDir.path)
        let dstBin = shellQuote(paths.systemHelperBinary.path)
        let srcBin = shellQuote(sourceHelper)
        let srcPlist = shellQuote(tempPlist.path)
        let dstPlist = shellQuote(paths.systemLaunchDaemonPlist.path)

        let shellCmd = [
            "mkdir -p \(sysDir)",
            "cp \(srcBin) \(dstBin)",
            "chown root:wheel \(sysDir) \(dstBin)",
            "chmod 755 \(sysDir) \(dstBin)",
            "cp \(srcPlist) \(dstPlist)",
            "chown root:wheel \(dstPlist)",
            "chmod 644 \(dstPlist)",
            "launchctl bootout system \(dstPlist) >/dev/null 2>&1 || true",
            "launchctl bootstrap system \(dstPlist) >/dev/null 2>&1 || launchctl load -w \(dstPlist) >/dev/null 2>&1 || true"
        ].joined(separator: " && ")

        try runWithAdminPrivileges(shellCmd)
    }

    /// 配置或移除当前用户的登录自启动 `LaunchAgent`。
    public static func setLaunchAtLogin(enabled: Bool, paths: GuardPaths = .live) {
        let fm = FileManager.default
        let plistURL = paths.userLaunchAgentPlist

        if !enabled {
            runProcess("/bin/launchctl", ["unload", plistURL.path])
            try? fm.removeItem(at: plistURL)
            return
        }

        guard let appExec = Bundle.main.executablePath else { return }
        let launchAgentsDir = plistURL.deletingLastPathComponent()
        try? fm.createDirectory(at: launchAgentsDir, withIntermediateDirectories: true)

        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(agentLabel)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(appExec)</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <dict>
                <key>SuccessfulExit</key>
                <false/>
            </dict>
        </dict>
        </plist>
        """
        try? Data(plist.utf8).write(to: plistURL, options: .atomic)
    }

    /// 紧急解除所有底层网络拦截与文件锁（无需卸载软件）。
    public static func emergencyUnblockAll(config: GuardConfig, paths: GuardPaths = .live) {
        UpdateFreezeManager.apply(freeze: false)
        _ = NetworkBlockStaging.stageAndTrigger(
            blockTargetDomains: false,
            blockClaudeUpdates: false,
            enabledTargets: config.targets,
            paths: paths,
            waitForApply: true
        )
    }

    /// 一键彻底无残留卸载：先恢复 `/etc/hosts`、清空 `com.apple/claudeguard` 锚点并释放 PF 令牌、解冻自动更新、还原 `claude` CLI、删除 LaunchDaemon 与 LaunchAgent。
    public static func uninstallEverything(config: GuardConfig, paths: GuardPaths = .live) throws {
        // 1. 先通过现有的特权助手或管理员权限清空网络规则并解冻更新目录
        UpdateFreezeManager.apply(freeze: false)
        CLIHookManager.removeAllLinks(configuredRealCLI: config.realClaudeCLIPath, paths: paths)
        setLaunchAtLogin(enabled: false, paths: paths)

        if isHelperInstalled(paths: paths) {
            _ = NetworkBlockStaging.stageAndTrigger(
                blockTargetDomains: false,
                blockClaudeUpdates: false,
                enabledTargets: [],
                paths: paths,
                waitForApply: true
            )

            let dstPlist = shellQuote(paths.systemLaunchDaemonPlist.path)
            let sysDir = shellQuote(paths.systemHelperDir.path)
            let tokenFile = "/Library/Application Support/ClaudeGuard/pf.token"
            let cleanupCmd = [
                "/sbin/pfctl -a com.apple/claudeguard -F all >/dev/null 2>&1 || true",
                "if [ -f '\(tokenFile)' ]; then /sbin/pfctl -X \"$(cat '\(tokenFile)')\" >/dev/null 2>&1 || true; fi",
                "launchctl bootout system \(dstPlist) >/dev/null 2>&1 || launchctl unload \(dstPlist) >/dev/null 2>&1 || true",
                "rm -rf \(dstPlist) \(sysDir)"
            ].joined(separator: " ; ")

            try runWithAdminPrivileges(cleanupCmd)
        }
    }

    private static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func runWithAdminPrivileges(_ shellCommand: String) throws {
        let escapedForAppleScript = shellCommand
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")

        let appleScript = "do shell script \"\(escapedForAppleScript)\" with administrator privileges"
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", appleScript]
        let errPipe = Pipe()
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = errPipe
        try proc.run()
        proc.waitUntilExit()

        if proc.terminationStatus != 0 {
            let errText = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            if errText.contains("-128") {
                throw NSError(
                    domain: "ClaudeGuard.Installer",
                    code: -128,
                    userInfo: [NSLocalizedDescriptionKey: "已取消管理员密码授权。"]
                )
            }
            throw NSError(
                domain: "ClaudeGuard.Installer",
                code: Int(proc.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "特权操作执行失败：\(errText.trimmingCharacters(in: .whitespacesAndNewlines))"]
            )
        }
    }

    private static func runProcess(_ path: String, _ args: [String]) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()
    }
}
