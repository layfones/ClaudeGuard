import Foundation

/// 偶发探测超时的防抖：刚确认放行后，若某一轮只是「没拿到结果」（判定为 `.offline`），
/// 先沿用上一次的放行结果，连续多次或超过宽限时间才真正进入「出口未确认」。
///
/// 安全取舍：
/// - 只对「没有结果」放宽；探测拿到了不在白名单里的出口（`.blocked`）时立即生效，不做任何等待；
/// - 宽限只在「上一次判定为放行」时生效，且有次数与时间双重上限；
/// - 代理断开时，HTTP 通常会直接返回本机真实 IP（判定为 `.blocked`），而不是超时，因此不会被宽限掩盖。
public struct TransientFailureDebouncer: Sendable {
    /// 允许连续沿用放行结果的「无结果」轮数（第 N+1 轮起正式判定为未确认）
    public var maxConsecutiveIncomplete: Int
    /// 距离上一次确认放行的最长宽限时间
    public var maxGraceSeconds: TimeInterval

    public private(set) var consecutiveIncomplete = 0
    public private(set) var lastConfirmedAllowedAt: Date?

    public init(maxConsecutiveIncomplete: Int = 2, maxGraceSeconds: TimeInterval = 15) {
        self.maxConsecutiveIncomplete = maxConsecutiveIncomplete
        self.maxGraceSeconds = maxGraceSeconds
    }

    /// 返回 `true` 表示本轮结果应当忽略，继续沿用上一次（放行）的判定与网络规则。
    public mutating func shouldHoldPrevious(newVerdict: GuardVerdict, previousVerdict: GuardVerdict, now: Date = Date()) -> Bool {
        switch newVerdict {
        case .allowed:
            consecutiveIncomplete = 0
            lastConfirmedAllowedAt = now
            return false

        case .offline:
            guard previousVerdict == .allowed,
                  let confirmed = lastConfirmedAllowedAt,
                  now.timeIntervalSince(confirmed) <= maxGraceSeconds,
                  consecutiveIncomplete < maxConsecutiveIncomplete else {
                consecutiveIncomplete = 0
                lastConfirmedAllowedAt = nil
                return false
            }
            consecutiveIncomplete += 1
            return true

        case .blocked, .paused:
            consecutiveIncomplete = 0
            lastConfirmedAllowedAt = nil
            return false
        }
    }
}
