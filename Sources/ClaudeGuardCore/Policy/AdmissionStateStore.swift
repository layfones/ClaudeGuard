import Foundation
import Darwin

/// 跨进程/跨重启持久化的准入状态（基准出口 IP、跳变锁定与分流泄漏锁定）。
public struct PersistedAdmissionState: Codable, Sendable, Equatable {
    public var baselineIPs: [String: String]
    public var jumpLatched: Bool
    public var jumpChannel: String?
    public var jumpBeforeIP: String?
    public var jumpAfterIP: String?
    /// 当通用 HTTP/STUN 走了代理，但目标域名（如 `claude.ai`）漏了直连时锁死，防止解封-重封循环震荡
    public var routeLeakLatched: Bool
    public var routeLeakMessage: String?

    public init(
        baselineIPs: [String: String] = [:],
        jumpLatched: Bool = false,
        jumpChannel: String? = nil,
        jumpBeforeIP: String? = nil,
        jumpAfterIP: String? = nil,
        routeLeakLatched: Bool = false,
        routeLeakMessage: String? = nil
    ) {
        self.baselineIPs = baselineIPs
        self.jumpLatched = jumpLatched
        self.jumpChannel = jumpChannel
        self.jumpBeforeIP = jumpBeforeIP
        self.jumpAfterIP = jumpAfterIP
        self.routeLeakLatched = routeLeakLatched
        self.routeLeakMessage = routeLeakMessage
    }
}

public final class AdmissionStateStore: Sendable {
    public let paths: GuardPaths
    private let inProcessLock = NSLock()

    public init(paths: GuardPaths = .live) {
        self.paths = paths
    }

    public func withExclusiveAccess<T>(_ body: (inout PersistedAdmissionState) -> T) -> T {
        inProcessLock.lock()
        defer { inProcessLock.unlock() }

        try? paths.ensureDirectoriesExist()
        let lockFD = open(paths.admissionLockFile.path, O_CREAT | O_RDWR, 0o600)
        if lockFD >= 0 {
            _ = flock(lockFD, LOCK_EX)
        }
        defer {
            if lockFD >= 0 {
                _ = flock(lockFD, LOCK_UN)
                close(lockFD)
            }
        }

        var state: PersistedAdmissionState
        if let data = try? Data(contentsOf: paths.admissionStateFile),
           let decoded = try? JSONDecoder().decode(PersistedAdmissionState.self, from: data) {
            state = decoded
        } else {
            state = PersistedAdmissionState()
        }

        let original = state
        let output = body(&state)

        if state != original,
           let encoded = try? JSONEncoder().encode(state) {
            try? encoded.write(to: paths.admissionStateFile, options: .atomic)
        }
        return output
    }

    public func resetAll() {
        withExclusiveAccess { state in
            state = PersistedAdmissionState()
        }
    }
}
