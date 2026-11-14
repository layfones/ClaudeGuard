import Foundation
import Darwin

/// 通过 BSD `uchg` 用户不可变标志与只读权限冻结/解冻 Claude Desktop 的 ShipIt 自动更新目录，
/// 配合 `/etc/hosts` 屏蔽更新域名与 CLI 环境变量注入，实现三层防自动更新。
public enum UpdateFreezeManager {
    public static func candidateUpdatePaths(
        homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> [URL] {
        let fm = FileManager.default
        var results: [URL] = []

        let cachesDir = homeDirectory.appendingPathComponent("Library/Caches", isDirectory: true)
        if let items = try? fm.contentsOfDirectory(at: cachesDir, includingPropertiesForKeys: nil) {
            for item in items {
                let name = item.lastPathComponent
                if name.hasPrefix("com.anthropic.claude") && name.hasSuffix(".ShipIt") {
                    results.append(item)
                }
            }
        }

        let appSupport = homeDirectory.appendingPathComponent("Library/Application Support", isDirectory: true)
        for sub in ["Claude/app-update.yml", "Claude-3p/app-update.yml"] {
            let file = appSupport.appendingPathComponent(sub)
            if fm.fileExists(atPath: file.path) {
                results.append(file)
            }
        }
        return results
    }

    public static func apply(freeze: Bool, homeDirectory: URL = FileManager.default.homeDirectoryForCurrentUser) {
        let targets = candidateUpdatePaths(homeDirectory: homeDirectory)
        guard !targets.isEmpty else { return }
        let fm = FileManager.default

        for url in targets {
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: url.path, isDirectory: &isDir) else { continue }
            if freeze {
                runCommand("/bin/chmod", args: isDir.boolValue ? ["-R", "444", url.path] : ["444", url.path])
                runCommand("/usr/bin/chflags", args: isDir.boolValue ? ["-R", "uchg", url.path] : ["uchg", url.path])
            } else {
                runCommand("/usr/bin/chflags", args: isDir.boolValue ? ["-R", "nouchg", url.path] : ["nouchg", url.path])
                runCommand("/bin/chmod", args: isDir.boolValue ? ["-R", "755", url.path] : ["644", url.path])
            }
        }
    }

    private static func runCommand(_ executable: String, args: [String]) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()
    }
}
