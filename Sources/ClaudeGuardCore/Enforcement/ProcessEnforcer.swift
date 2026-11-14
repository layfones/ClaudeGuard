import Foundation
import AppKit
import Darwin

/// 负责匹配并毫秒级终止受保护的 AI 桌面客户端及其内嵌子进程（如 Claude Desktop 内嵌的 `Claude-3p/.../claude.app`）。
public enum ProcessEnforcer {
    /// 判断某个 `NSRunningApplication` 是否命中任意已启用的守护目标（严格排除 ClaudeGuard 自身）。
    public static func matchedTarget(
        for app: NSRunningApplication,
        in enabledTargets: [GuardedTarget]
    ) -> GuardedTarget? {
        if app.processIdentifier == getpid() { return nil }
        if let bundleID = app.bundleIdentifier {
            if bundleID.hasPrefix("com.claudeguard") {
                return nil
            }
            for target in enabledTargets {
                for prefix in target.bundleIDPrefixes where !prefix.isEmpty {
                    if bundleID == prefix || bundleID.hasPrefix(prefix) {
                        return target
                    }
                }
            }
        }

        if let execPath = app.executableURL?.path {
            if execPath.contains("ClaudeGuard") { return nil }
            for target in enabledTargets {
                if target.processPathKeywords.contains(where: { !$0.isEmpty && execPath.contains($0) }) {
                    return target
                }
            }
        }
        return nil
    }

    /// 强力终止单个刚启动的受限应用及其后台辅助进程。
    public static func forceTerminateApp(_ app: NSRunningApplication, target: GuardedTarget) {
        _ = app.forceTerminate()
        terminateMatchingSubprocesses(for: [target])
    }

    /// 扫描当前运行的所有应用与关联后台进程并立即关停，返回被终止的目标名称列表。
    public static func terminateRunningGuardedApps(enabledTargets: [GuardedTarget]) -> [String] {
        guard !enabledTargets.isEmpty else { return [] }
        var terminatedNames = Set<String>()

        for app in NSWorkspace.shared.runningApplications {
            if let matched = matchedTarget(for: app, in: enabledTargets) {
                if app.forceTerminate() || app.terminate() {
                    terminatedNames.insert(matched.name)
                }
            }
        }

        let killedFromPS = terminateMatchingSubprocesses(for: enabledTargets)
        terminatedNames.formUnion(killedFromPS)
        return terminatedNames.sorted()
    }

    /// 扫描 `ps -axo pid=,command=` 精确清理漏网的内嵌进程（例如 `Claude-3p/.../claude.app/Contents/MacOS/claude`）。
    @discardableResult
    public static func terminateMatchingSubprocesses(for targets: [GuardedTarget]) -> Set<String> {
        let keywordsWithTarget: [(keyword: String, targetName: String)] = targets.flatMap { t in
            t.processPathKeywords.filter { !$0.isEmpty }.map { ($0, t.name) }
        }
        guard !keywordsWithTarget.isEmpty else { return [] }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/ps")
        proc.arguments = ["-axo", "pid=,command="]
        let outPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
        } catch {
            return []
        }
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()

        guard let output = String(data: data, encoding: .utf8) else { return [] }
        let myPID = getpid()
        var matchedTargetNames = Set<String>()
        var victimPIDs: [pid_t] = []

        for rawLine in output.split(whereSeparator: \.isNewline) {
            let trimmed = rawLine.trimmingCharacters(in: .whitespaces)
            guard let spaceIdx = trimmed.firstIndex(where: \.isWhitespace) else { continue }
            guard let pid = Int32(trimmed[..<spaceIdx]), pid > 1, pid != myPID else { continue }
            let cmd = String(trimmed[spaceIdx...]).trimmingCharacters(in: .whitespaces)
            if cmd.contains("ClaudeGuard") || cmd.contains("claudeguard") {
                continue
            }

            for (kw, tName) in keywordsWithTarget where cmd.contains(kw) {
                victimPIDs.append(pid)
                matchedTargetNames.insert(tName)
                break
            }
        }

        guard !victimPIDs.isEmpty else { return [] }
        for pid in victimPIDs {
            _ = kill(pid, SIGTERM)
        }
        usleep(120_000)
        for pid in victimPIDs {
            if kill(pid, 0) == 0 {
                _ = kill(pid, SIGKILL)
            }
        }
        return matchedTargetNames
    }

    /// 启动本机已安装的 `v2rayN.app`（供拦截弹窗一键唤起）。
    @discardableResult
    public static func launchV2rayNIfInstalled() -> Bool {
        let snapshot = ProxyEnvironmentDetector.inspect()
        if let path = snapshot.v2rayNAppPath {
            let url = URL(fileURLWithPath: path)
            NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
            return true
        }
        if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: ProxyEnvironmentDetector.v2rayNBundleID) {
            NSWorkspace.shared.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
            return true
        }
        return false
    }
}
