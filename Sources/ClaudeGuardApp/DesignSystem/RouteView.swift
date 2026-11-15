import SwiftUI
import ClaudeGuardCore

/// 标志性元素「三线归一」：HTTP、目标网站真实链路与 UDP 三条探测线从本机出发，
/// 收敛到同一个白名单出口才放行；变红、分叉或中断的线路就是出问题的地方。
struct RouteView: View {
    let route: RoutePresentation
    var width: CGFloat = 308

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var progress: CGFloat = 1

    private let laneGap: CGFloat = 28
    private let topInset: CGFloat = 18

    private var laneCount: Int { max(route.lanes.count, 1) }
    private var height: CGFloat { topInset + CGFloat(laneCount - 1) * laneGap + 20 }
    private var originY: CGFloat { topInset + CGFloat(laneCount - 1) * laneGap / 2 }
    private var straightEnd: CGFloat { (width * 0.455).rounded() }
    private var mergeX: CGFloat { (width * 0.584).rounded() }
    private var stopX: CGFloat { straightEnd - 22 }
    private var exitCenter: CGPoint { CGPoint(x: mergeX + 8, y: originY) }
    private var textX: CGFloat { exitCenter.x + 20 }

    private func laneY(_ index: Int) -> CGFloat { topInset + CGFloat(index) * laneGap }

    /// 线路状态变化时重放一次收敛动画（常规轮询不触发）
    private var animationKey: String {
        route.lanes.map { "\($0.id):\($0.state):\($0.diverges)" }.joined(separator: "|") + "→\(route.exit.state)"
    }

    var body: some View {
        ZStack(alignment: .topLeading) {
            ForEach(Array(route.lanes.enumerated()), id: \.element.id) { index, lane in
                laneStroke(lane, y: laneY(index))
                laneLabels(lane, y: laneY(index))
                laneTerminal(lane, y: laneY(index))
            }

            Circle()
                .fill(Color(nsColor: .windowBackgroundColor))
                .overlay(Circle().strokeBorder(.secondary, lineWidth: 1.6))
                .frame(width: 10, height: 10)
                .offset(x: 3, y: originY - 5)

            exitNode
                .opacity(progress > 0.85 ? 1 : 0)
        }
        .frame(width: width, height: height, alignment: .topLeading)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("出口线路")
        .accessibilityValue(route.accessibilitySummary)
        .onChange(of: animationKey) { _, _ in replay() }
    }

    // MARK: - 线路

    private func laneColor(_ lane: RouteLane) -> Color {
        switch lane.state {
        case .fail:
            return .guardBlock
        case .pass:
            return route.exit.state == .fail && !lane.diverges ? .guardBlock : .secondary
        case .sealed, .missing, .idle:
            return .secondary
        }
    }

    private func laneOpacity(_ lane: RouteLane) -> Double {
        switch lane.state {
        case .fail: return 1
        case .pass: return route.exit.state == .fail ? 1 : 0.55
        case .sealed, .missing: return 0.6
        case .idle: return 0.35
        }
    }

    private func converges(_ lane: RouteLane) -> Bool {
        !lane.diverges && (lane.state == .pass || lane.state == .fail || lane.state == .idle)
    }

    @ViewBuilder
    private func laneStroke(_ lane: RouteLane, y: CGFloat) -> some View {
        let dashed = lane.state == .sealed || lane.state == .missing
        LaneShape(
            laneY: y, originY: originY,
            converges: converges(lane),
            straightEnd: straightEnd, mergeX: mergeX, stopX: stopX
        )
        .trim(from: 0, to: progress)
        .stroke(
            laneColor(lane).opacity(laneOpacity(lane)),
            style: StrokeStyle(lineWidth: 2, lineCap: .round, dash: dashed ? [2, 5] : [])
        )
        .frame(width: width, height: height)
    }

    @ViewBuilder
    private func laneLabels(_ lane: RouteLane, y: CGFloat) -> some View {
        Text(lane.label)
            .font(.subheadline)
            .foregroundStyle(.secondary)
            .fixedSize()
            .offset(x: 44, y: y - 17)

        if let ms = lane.latencyMs, lane.state == .pass || lane.state == .fail {
            Text("\(ms) ms")
                .font(.footnote)
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .frame(width: straightEnd - 2, alignment: .trailing)
                .offset(y: y - 15)
        }
    }

    @ViewBuilder
    private func laneTerminal(_ lane: RouteLane, y: CGFloat) -> some View {
        switch lane.state {
        case .sealed, .missing:
            HStack(spacing: 4) {
                Image(systemName: lane.state == .sealed ? "lock" : "clock")
                    .font(.system(size: 11, weight: .semibold))
                Text(lane.state == .sealed ? "已封锁" : "未响应")
                    .font(.footnote)
            }
            .foregroundStyle(.secondary)
            .fixedSize()
            .offset(x: stopX + 2, y: y - 7)
            .opacity(progress > 0.85 ? 1 : 0)
        case .fail where lane.diverges, .pass where lane.diverges:
            let isFail = lane.state == .fail
            Circle()
                .fill(isFail ? Color.guardBlock : Color.secondary)
                .frame(width: 12, height: 12)
                .offset(x: stopX - 4, y: y - 6)
                .opacity(progress > 0.85 ? 1 : 0)
            Text(isFail ? "\(lane.ip ?? "") · 直连" : (lane.ip ?? ""))
                .font(.subheadline)
                .monospacedDigit()
                .foregroundStyle(.primary)
                .fixedSize()
                .offset(x: stopX + 16, y: y - 8)
                .opacity(progress > 0.85 ? 1 : 0)
        default:
            EmptyView()
        }
    }

    // MARK: - 出口

    private var exitColor: Color {
        switch route.exit.state {
        case .pass: return .guardPass
        case .fail: return .guardBlock
        case .unknown: return .guardHold
        case .idle: return .secondary
        }
    }

    private var exitGlyph: String? {
        switch route.exit.state {
        case .pass: return "checkmark"
        case .fail: return "xmark"
        case .unknown: return "questionmark"
        case .idle: return nil
        }
    }

    @ViewBuilder
    private var exitNode: some View {
        let c = exitCenter
        Circle()
            .fill(exitColor.opacity(route.exit.state == .idle ? 0.1 : 0.16))
            .frame(width: 28, height: 28)
            .offset(x: c.x - 14, y: c.y - 14)
        Circle()
            .fill(exitColor.opacity(route.exit.state == .idle ? 0.45 : 1))
            .frame(width: 18, height: 18)
            .overlay {
                if let glyph = exitGlyph {
                    Image(systemName: glyph)
                        .font(.system(size: 9, weight: .heavy))
                        .foregroundStyle(.white)
                }
            }
            .offset(x: c.x - 9, y: c.y - 9)

        VStack(alignment: .leading, spacing: 1) {
            Text(route.exit.ip ?? "未获取出口")
                .font(.headline)
                .monospacedDigit()
                .foregroundStyle(route.exit.ip == nil ? .secondary : .primary)
                .textSelection(.enabled)
            if !route.exit.metaText.isEmpty {
                Text(route.exit.metaText)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
        .lineLimit(1)
        .frame(width: width - textX, alignment: .leading)
        .offset(x: textX, y: c.y - (route.exit.metaText.isEmpty ? 9 : 18))
    }

    private func replay() {
        guard !reduceMotion else {
            progress = 1
            return
        }
        progress = 0
        withAnimation(.easeOut(duration: 0.55)) {
            progress = 1
        }
    }
}

/// 单条线路：从本机原点扇出，平行前进，再收敛到出口；不收敛的线路停在 `stopX`。
private struct LaneShape: Shape {
    var laneY: CGFloat
    var originY: CGFloat
    var converges: Bool
    var straightEnd: CGFloat
    var mergeX: CGFloat
    var stopX: CGFloat

    func path(in rect: CGRect) -> Path {
        var p = Path()
        let startX: CGFloat = 12
        p.move(to: CGPoint(x: startX, y: originY))
        if abs(laneY - originY) < 0.5 {
            p.addLine(to: CGPoint(x: converges ? mergeX : stopX, y: originY))
            return p
        }
        p.addCurve(
            to: CGPoint(x: 40, y: laneY),
            control1: CGPoint(x: 26, y: originY),
            control2: CGPoint(x: 26, y: laneY)
        )
        if converges {
            p.addLine(to: CGPoint(x: straightEnd, y: laneY))
            p.addCurve(
                to: CGPoint(x: mergeX, y: originY),
                control1: CGPoint(x: straightEnd + 22, y: laneY),
                control2: CGPoint(x: straightEnd + 22, y: originY)
            )
        } else {
            p.addLine(to: CGPoint(x: stopX, y: laneY))
        }
        return p
    }
}
