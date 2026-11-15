import SwiftUI
import AppKit
import ClaudeGuardCore

/// 菜单栏状态面板（`MenuBarExtra(.window)`，macOS 26 起由系统提供 Liquid Glass 背景）。
/// 只回答一个问题：现在打开 Claude 安全吗？——判定、线路图、两行明细、唯一主操作。
struct StatusPopoverView: View {
    @Bindable var coordinator: GuardCoordinator
    var openSetupAction: () -> Void
    /// 传入 nil 时恢复上次查看的设置面板
    var openSettingsAction: (SettingsTab?) -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var showQuickAddIP = false
    @State private var quickAddRemark = ""

    private var installedTargetIDs: Set<String> {
        Set(coordinator.config.targets.filter { ProcessEnforcer.resolveInstalledAppURL(for: $0) != nil }.map(\.id))
    }

    private var verdict: VerdictPresentation {
        VerdictPresenter.make(
            state: coordinator.state,
            config: coordinator.config,
            context: .init(
                helperInstalled: coordinator.state.helperInstalled,
                publicIPv6Disabled: coordinator.systemIPv6Status.isPublicIPv6DisabledOnAll,
                installedTargetIDs: installedTargetIDs
            )
        )
    }

    private var canQuickAddCurrentIP: Bool {
        guard verdict.tone == .block,
              !coordinator.state.jumpLatched,
              !(coordinator.state.proxyEnvironment.isV2rayNInstalled && !coordinator.state.proxyEnvironment.isV2rayNRunning),
              let ip = coordinator.state.primaryIP,
              CIDRMatcher.isValidLiteralIP(ip) else {
            return false
        }
        return CIDRMatcher.firstMatchingEntry(for: ip, in: coordinator.config.enabledAllowedIPs) == nil
    }

    var body: some View {
        let verdict = self.verdict
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                titleRow
                hero(verdict)
                RouteView(route: RoutePresenter.make(state: coordinator.state, config: coordinator.config))
                detailRows
                Divider()
                guardedApps
                actionArea(verdict)
            }
            .padding(.horizontal, 16)
            .padding(.top, 14)
            .padding(.bottom, 12)

            Divider()
                .padding(.horizontal, 16)

            menuRows
                .padding(6)
        }
        .frame(width: 340)
    }

    // MARK: - 标题行：名称 · 重新检测 · 总开关

    private var titleRow: some View {
        HStack(spacing: 6) {
            Text("ClaudeGuard")
                .font(.headline)

            Spacer(minLength: 4)

            Button {
                coordinator.triggerRecheck()
            } label: {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 13, weight: .medium))
                    .rotationEffect(.degrees(!reduceMotion && coordinator.isChecking ? 360 : 0))
                    .animation(
                        !reduceMotion && coordinator.isChecking
                            ? .linear(duration: 0.9).repeatForever(autoreverses: false)
                            : .default,
                        value: coordinator.isChecking
                    )
                    .frame(width: 28, height: 28)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.secondary)
            .help("重新检测出口")
            .accessibilityLabel("重新检测出口")

            Toggle("守护", isOn: Binding(
                get: { coordinator.config.protectionEnabled },
                set: { coordinator.toggleProtection($0) }
            ))
            .labelsHidden()
            .toggleStyle(.switch)
            .controlSize(.small)
            .accessibilityLabel("守护开关")
        }
    }

    // MARK: - 判定

    private func hero(_ v: VerdictPresentation) -> some View {
        HStack(alignment: .top, spacing: 12) {
            VerdictGlyph(tone: v.tone, symbol: v.symbol)
            VStack(alignment: .leading, spacing: 2) {
                Text(v.title)
                    .font(.system(size: 20, weight: .bold))
                    .fixedSize(horizontal: false, vertical: true)
                Text(v.message)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
    }

    // MARK: - 明细

    private var detailRows: some View {
        VStack(spacing: 2) {
            ForEach(StatusDetailPresenter.make(
                state: coordinator.state,
                config: coordinator.config,
                helperInstalled: coordinator.state.helperInstalled
            )) { row in
                HStack(spacing: 8) {
                    Image(systemName: row.symbol)
                        .font(.system(size: 13))
                        .foregroundStyle(.secondary)
                        .frame(width: 16)
                        .accessibilityHidden(true)
                    Text(row.label)
                    Spacer(minLength: 8)
                    Text(row.value)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .font(.body)
                .frame(minHeight: 24)
                .accessibilityElement(children: .combine)
            }
        }
    }

    // MARK: - 守护的应用

    private var guardedApps: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("守护的应用")
                .font(.subheadline.weight(.medium))
                .foregroundStyle(.secondary)
            ChipFlowLayout(spacing: 6) {
                ForEach(coordinator.config.targets) { target in
                    GuardChip(title: VerdictPresenter.shortName(target.name), isOn: target.isEnabled) {
                        coordinator.updateConfig { cfg in
                            if let idx = cfg.targets.firstIndex(where: { $0.id == target.id }) {
                                cfg.targets[idx].isEnabled.toggle()
                            }
                        }
                    }
                    .help(target.isEnabled ? "停止守护 \(target.name)" : "开始守护 \(target.name)")
                }
            }
        }
    }

    // MARK: - 唯一主操作

    @ViewBuilder
    private func actionArea(_ v: VerdictPresentation) -> some View {
        if let action = v.action, let title = v.actionTitle {
            VStack(spacing: 8) {
                Button {
                    perform(action)
                } label: {
                    Text(title)
                        .frame(maxWidth: .infinity)
                }
                .guardProminentButton()
                .controlSize(.large)
                .disabled(action == .disablePublicIPv6 && coordinator.isSwitchingIPv6)

                if let hint = v.hint {
                    Text(hint)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: .infinity)
                }
            }
        }

        if canQuickAddCurrentIP, let ip = coordinator.state.primaryIP {
            quickAdd(ip: ip)
        }

        if let msg = coordinator.lastActionMessage {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Image(systemName: coordinator.lastActionIsError ? "exclamationmark.circle" : "checkmark.circle")
                    .foregroundStyle(coordinator.lastActionIsError ? Color.guardBlock : .secondary)
                Text(msg)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
                Button {
                    coordinator.setBanner(nil, isError: false)
                } label: {
                    Image(systemName: "xmark")
                        .font(.system(size: 9, weight: .bold))
                        .frame(width: 20, height: 20)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
                .accessibilityLabel("关闭提示")
            }
        }
    }

    @ViewBuilder
    private func quickAdd(ip: String) -> some View {
        if showQuickAddIP {
            VStack(alignment: .leading, spacing: 6) {
                Text("先确认 v2rayN 已连上，再把 \(ip) 加入白名单。")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 6) {
                    TextField("备注，例如：洛杉矶主力", text: $quickAddRemark)
                        .textFieldStyle(.roundedBorder)
                    Button("加入") {
                        let fallback = coordinator.state.primaryCountryCode.map { "\(RoutePresenter.regionName(for: $0))节点" } ?? "代理节点"
                        if coordinator.addAllowedIP(cidrOrIP: ip, label: quickAddRemark.isEmpty ? fallback : quickAddRemark) {
                            quickAddRemark = ""
                            withAnimation(.easeInOut(duration: 0.18)) { showQuickAddIP = false }
                        }
                    }
                    Button("取消") {
                        withAnimation(.easeInOut(duration: 0.18)) { showQuickAddIP = false }
                    }
                }
                .controlSize(.small)
            }
        } else {
            Button("这是我的代理出口？加入白名单…") {
                withAnimation(.easeInOut(duration: 0.18)) { showQuickAddIP = true }
            }
            .buttonStyle(.link)
            .font(.subheadline)
            .frame(maxWidth: .infinity)
        }
    }

    private func perform(_ action: VerdictPresentation.Action) {
        switch action {
        case .openSetup:
            openSetupAction()
        case .resumeProtection:
            coordinator.toggleProtection(true)
        case .trustNewExit, .recheckRouteLeak:
            coordinator.acknowledgeCurrentExitJump()
        case .launchV2rayN, .openV2rayN:
            coordinator.launchV2rayN()
        case .disablePublicIPv6:
            coordinator.toggleSystemPublicIPv6(disable: true)
        case .launchTarget(let id):
            if let target = coordinator.config.targets.first(where: { $0.id == id }) {
                coordinator.launchGuardedAppAligned(target)
            }
        }
    }

    // MARK: - 菜单行

    private var menuRows: some View {
        VStack(spacing: 0) {
            MenuRowButton(title: "设置…", shortcut: "⌘,") {
                openSettingsAction(nil)
            }
            .keyboardShortcut(",", modifiers: .command)

            MenuRowButton(title: "拦截记录") {
                openSettingsAction(.logs)
            }

            MenuRowButton(title: "退出 ClaudeGuard", shortcut: "⌘Q") {
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q", modifiers: .command)
            .help("退出后，已经写入的网络封锁会一直保持，直到出口恢复正常并重新放行。")
        }
    }
}

/// 自动换行排布的胶囊组。
struct ChipFlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, rowHeight: CGFloat = 0, widest: CGFloat = 0
        for sub in subviews {
            let size = sub.sizeThatFits(.unspecified)
            if x > 0 && x + size.width > maxWidth {
                y += rowHeight + spacing
                x = 0
                rowHeight = 0
            }
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
            widest = max(widest, x - spacing)
        }
        return CGSize(width: proposal.width ?? widest, height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowHeight: CGFloat = 0
        for sub in subviews {
            let size = sub.sizeThatFits(.unspecified)
            if x > bounds.minX && x + size.width > bounds.maxX {
                y += rowHeight + spacing
                x = bounds.minX
                rowHeight = 0
            }
            sub.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}
