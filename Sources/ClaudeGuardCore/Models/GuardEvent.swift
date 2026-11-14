import Foundation

public enum GuardEventKind: String, Codable, Sendable {
    case guardStarted = "guard_started"
    case verdictChanged = "verdict_changed"
    case appLaunchIntercepted = "app_launch_intercepted"
    case runningAppTerminated = "running_app_terminated"
    case cliSessionBlocked = "cli_session_blocked"
    case ipJumpLatched = "ip_jump_latched"
    case ipJumpAcknowledged = "ip_jump_acknowledged"
    case networkSyncApplied = "network_sync_applied"
    case helperInstalled = "helper_installed"
    case emergencyUnblocked = "emergency_unblocked"
    case probeWarning = "probe_warning"

    public var label: String {
        switch self {
        case .guardStarted: return "守护启动"
        case .verdictChanged: return "状态变更"
        case .appLaunchIntercepted: return "启动拦截"
        case .runningAppTerminated: return "熔断关停"
        case .cliSessionBlocked: return "CLI 拦截"
        case .ipJumpLatched: return "跳变锁定"
        case .ipJumpAcknowledged: return "信任新出口"
        case .networkSyncApplied: return "规则同步"
        case .helperInstalled: return "防线部署"
        case .emergencyUnblocked: return "紧急解封"
        case .probeWarning: return "探测异常"
        }
    }
}

public struct GuardEvent: Codable, Sendable, Equatable, Identifiable {
    public var id: UUID
    public var timestamp: Date
    public var kind: GuardEventKind
    public var message: String
    public var detectedIP: String?
    public var targetName: String?

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        kind: GuardEventKind,
        message: String,
        detectedIP: String? = nil,
        targetName: String? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.kind = kind
        self.message = message
        self.detectedIP = detectedIP
        self.targetName = targetName
    }
}

/// 结构化 JSONL 日志记录器，超过 1 MiB 自动轮转为 `events.jsonl.1`。
public final class EventLogger: Sendable {
    public let paths: GuardPaths
    private let lock = NSLock()
    private let maxBytes = 1_048_576

    public init(paths: GuardPaths = .live) {
        self.paths = paths
    }

    public func append(
        _ kind: GuardEventKind,
        message: String,
        detectedIP: String? = nil,
        targetName: String? = nil
    ) {
        let event = GuardEvent(
            kind: kind,
            message: message,
            detectedIP: detectedIP,
            targetName: targetName
        )
        lock.lock()
        defer { lock.unlock() }
        do {
            try paths.ensureDirectoriesExist()
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            var line = try encoder.encode(event)
            line.append(0x0A)

            let fm = FileManager.default
            let currentSize = (try? fm.attributesOfItem(atPath: paths.eventsFile.path)[.size] as? Int) ?? 0
            if currentSize + line.count > maxBytes {
                let backup = paths.eventsFile.appendingPathExtension("1")
                try? fm.removeItem(at: backup)
                if fm.fileExists(atPath: paths.eventsFile.path) {
                    try? fm.moveItem(at: paths.eventsFile, to: backup)
                }
            }
            if !fm.fileExists(atPath: paths.eventsFile.path) {
                fm.createFile(
                    atPath: paths.eventsFile.path,
                    contents: nil,
                    attributes: [.posixPermissions: 0o600]
                )
            }
            let handle = try FileHandle(forWritingTo: paths.eventsFile)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: line)
        } catch {
            // 日志失败绝不影响主防护流程
        }
    }

    public func readRecent(limit: Int = 200) -> [GuardEvent] {
        lock.lock()
        defer { lock.unlock() }
        guard let raw = try? String(contentsOf: paths.eventsFile, encoding: .utf8) else {
            return []
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let lines = raw.split(whereSeparator: \.isNewline).suffix(limit)
        return lines.compactMap { line in
            guard let data = String(line).data(using: .utf8) else { return nil }
            return try? decoder.decode(GuardEvent.self, from: data)
        }.reversed()
    }

    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        try? FileManager.default.removeItem(at: paths.eventsFile)
        try? FileManager.default.removeItem(at: paths.eventsFile.appendingPathExtension("1"))
    }
}
