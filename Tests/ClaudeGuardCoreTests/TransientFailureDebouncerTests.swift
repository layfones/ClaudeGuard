import XCTest
@testable import ClaudeGuardCore

final class TransientFailureDebouncerTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    func testSingleTimeoutAfterAllowedIsHeld() {
        var d = TransientFailureDebouncer()
        XCTAssertFalse(d.shouldHoldPrevious(newVerdict: .allowed, previousVerdict: .offline, now: t0))
        XCTAssertTrue(d.shouldHoldPrevious(newVerdict: .offline, previousVerdict: .allowed, now: t0.addingTimeInterval(3)))
        // 下一轮恢复正常，计数清零
        XCTAssertFalse(d.shouldHoldPrevious(newVerdict: .allowed, previousVerdict: .allowed, now: t0.addingTimeInterval(6)))
        XCTAssertEqual(d.consecutiveIncomplete, 0)
    }

    func testRepeatedTimeoutsEventuallyCount() {
        var d = TransientFailureDebouncer(maxConsecutiveIncomplete: 2, maxGraceSeconds: 60)
        _ = d.shouldHoldPrevious(newVerdict: .allowed, previousVerdict: .offline, now: t0)
        XCTAssertTrue(d.shouldHoldPrevious(newVerdict: .offline, previousVerdict: .allowed, now: t0.addingTimeInterval(3)))
        XCTAssertTrue(d.shouldHoldPrevious(newVerdict: .offline, previousVerdict: .allowed, now: t0.addingTimeInterval(6)))
        XCTAssertFalse(d.shouldHoldPrevious(newVerdict: .offline, previousVerdict: .allowed, now: t0.addingTimeInterval(9)), "第 3 次连续无结果应正式判定为未确认")
    }

    func testGraceExpiresByTime() {
        var d = TransientFailureDebouncer(maxConsecutiveIncomplete: 5, maxGraceSeconds: 15)
        _ = d.shouldHoldPrevious(newVerdict: .allowed, previousVerdict: .offline, now: t0)
        XCTAssertFalse(d.shouldHoldPrevious(newVerdict: .offline, previousVerdict: .allowed, now: t0.addingTimeInterval(20)))
    }

    func testBlockedIsNeverHeld() {
        var d = TransientFailureDebouncer()
        _ = d.shouldHoldPrevious(newVerdict: .allowed, previousVerdict: .offline, now: t0)
        XCTAssertFalse(d.shouldHoldPrevious(newVerdict: .blocked, previousVerdict: .allowed, now: t0.addingTimeInterval(1)), "拿到非白名单出口必须立即拦截")
        // 拦截后不再享有宽限：需要重新确认放行
        XCTAssertFalse(d.shouldHoldPrevious(newVerdict: .offline, previousVerdict: .allowed, now: t0.addingTimeInterval(2)))
    }

    func testNoGraceWithoutPriorAllowed() {
        var d = TransientFailureDebouncer()
        XCTAssertFalse(d.shouldHoldPrevious(newVerdict: .offline, previousVerdict: .offline, now: t0))
        XCTAssertFalse(d.shouldHoldPrevious(newVerdict: .offline, previousVerdict: .allowed, now: t0), "从未确认过放行时不应宽限")
    }
}
