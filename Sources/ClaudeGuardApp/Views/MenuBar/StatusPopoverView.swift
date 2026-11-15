import SwiftUI
import AppKit
import ClaudeGuardCore

struct StatusPopoverView: View {
    @Bindable var coordinator: GuardCoordinator
    var openSetupAction: () -> Void
    var openSettingsAction: (SettingsTab) -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var showQuickAddIP = false
    @State private var quickAddRemark = ""
    @State private var copiedIPFeedback = false

    private var verdictColor: Color {
        switch coordinator.state.verdict {
        case .allowed: return .green
        case .blocked: return .red
        case .offline: return .orange
        case .paused:  return .secondary
        }
    }

    private var canQuickAddCurrentIP: Bool {
        guard let ip = coordinator.state.primaryIP,
              CIDRMatcher.isValidLiteralIP(ip) else {
            return false
        }
        return CIDRMatcher.firstMatchingEntry(for: ip, in: coordinator.config.enabledAllowedIPs) == nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            headerSection

            if !coordinator.config.onboardingCompleted || !coordinator.state.helperInstalled {
                onboardingCalloutCard
            } else if coordinator.config.protectionEnabled && coordinator.state.verdict != .allowed {
                recoveryActionCard
            }

            egressOverviewCard

            channelBreakdownCard

            quickModeAndTargetsBar

            if let msg = coordinator.lastActionMessage {
                HStack(spacing: 6) {
                    Image(systemName: coordinator.lastActionIsError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                        .foregroundStyle(coordinator.lastActionIsError ? .red : .green)
                    Text(msg)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                    Spacer(minLength: 0)
                    Button {
                        coordinator.setBanner(nil, isError: false)
                    } label: {
                        Image(systemName: "xmark")
                            .font(.caption2)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("关闭提示")
                }
                .padding(.horizontal, 4)
            }

            Divider()

            footerBar
        }
        .padding(14)
        .frame(width: 356)
    }

    // MARK: - 1. 顶部状态总览与主开关

    private var headerSection: some View {
        HStack(spacing: 10) {
            ZStack {
                Circle()
                    .fill(verdictColor.opacity(0.16))
                    .frame(width: 38, height: 38)
                Image(systemName: coordinator.state.verdict.sfSymbolName)
                    .font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(verdictColor)
            }
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(coordinator.state.verdict.title)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(.primary)
                Text(coordinator.state.reason)
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }

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
            }
            .buttonStyle(.borderless)
            .help("立即重新检测所有出口链路")
            .accessibilityLabel("立即重新检测")

            Toggle("启用守护", isOn: Binding(
                get: { coordinator.config.protectionEnabled },
                set: { coordinator.toggleProtection($0) }
            ))
            .labelsHidden()
            .toggleStyle(.switch)
            .controlSize(.small)
            .accessibilityLabel("总防护开关")
        }
    }

    // MARK: - 2. 引导 / 异常一键恢复条

    private var onboardingCalloutCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(
                !coordinator.state.helperInstalled ? "尚未启用系统级网络防线" : "差一步完成初始白名单配置",
                systemImage: "sparkles"
            )
            .font(.system(size: 12.5, weight: .semibold))

            Text("完成 1 分钟向导后，即使忘记开启 v2rayN 直接点 Dock 启动 Claude，也能在内核层零泄漏拦下。")
                .font(.system(size: 11.5))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Button {
                openSetupAction()
            } label: {
                Label("打开快速配置向导…", systemImage: "wand.and.stars")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.regular)
        }
        .padding(10)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    private var recoveryActionCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            if coordinator.state.proxyEnvironment.isV2rayNInstalled && !coordinator.state.proxyEnvironment.isV2rayNRunning {
                Button {
                    coordinator.launchV2rayN()
                } label: {
                    Label("检测到 v2rayN 未运行 · 一键启动 v2rayN", systemImage: "paperplane.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.regular)
            }

            if coordinator.state.jumpLatched {
                Button {
                    coordinator.acknowledgeCurrentExitJump()
                } label: {
                    Label("信任当前新出口并解除锁定", systemImage: "checkmark.seal.fill")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.regular)
            }

            if canQuickAddCurrentIP, let currentIP = coordinator.state.primaryIP {
                if showQuickAddIP {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("将当前出口 \(currentIP) 加入白名单（确认代理已开启后再添加）：")
                            .font(.system(size: 11.5, weight: .medium))
                        HStack(spacing: 6) {
                            TextField("节点备注（如：美西主力节点）", text: $quickAddRemark)
                                .textFieldStyle(.roundedBorder)
                                .controlSize(.small)
                            Button("保存") {
                                let defaultName = coordinator.state.primaryCountryCode.map { "\($0) 代理节点" } ?? "代理节点"
                                if coordinator.addAllowedIP(
                                    cidrOrIP: currentIP,
                                    label: quickAddRemark.isEmpty ? defaultName : quickAddRemark
                                ) {
                                    quickAddRemark = ""
                                    withAnimation(.easeInOut(duration: 0.18)) {
                                        showQuickAddIP = false
                                    }
                                }
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.small)

                            Button("取消") {
                                withAnimation(.easeInOut(duration: 0.18)) {
                                    showQuickAddIP = false
                                }
                            }
                            .controlSize(.small)
                        }
                    }
                } else {
                    Button {
                        withAnimation(.easeInOut(duration: 0.18)) {
                            showQuickAddIP = true
                        }
                    } label: {
                        Label("将当前出口 \(currentIP) 加入白名单…", systemImage: "plus.circle")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
        }
    }

    // MARK: - 3. 当前主出口与代理环境信息卡

    private var egressOverviewCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text("当前主出口")
                    .font(.system(size: 11.5, weight: .medium))
                    .foregroundStyle(.secondary)

                Spacer()

                if let label = coordinator.state.matchedWhitelistLabel {
                    Label(label, systemImage: "tag.fill")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(.green)
                }
            }

            HStack(spacing: 8) {
                Text(coordinator.state.primaryIP ?? "暂未获取出口")
                    .font(.system(size: 16, weight: .semibold, design: .monospaced))
                    .textSelection(.enabled)

                if let cc = coordinator.state.primaryCountryCode {
                    Text(cc)
                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.quaternary, in: Capsule())
                }

                Spacer()

                if let ip = coordinator.state.primaryIP {
                    Button {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(ip, forType: .string)
                        copiedIPFeedback = true
                        Task {
                            try? await Task.sleep(for: .seconds(1.5))
                            copiedIPFeedback = false
                        }
                    } label: {
                        Image(systemName: copiedIPFeedback ? "checkmark" : "doc.on.doc")
                            .font(.system(size: 11.5))
                            .frame(width: 24, height: 24)
                    }
                    .buttonStyle(.borderless)
                    .help("复制出口 IP")
                    .accessibilityLabel("复制出口 IP")
                }
            }

            HStack(spacing: 6) {
                Image(systemName: !coordinator.state.proxyEnvironment.activeTUNInterfaces.isEmpty ? "network.badge.shield.half.filled" : "antenna.radiowaves.left.and.right")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                Text(coordinator.state.proxyEnvironment.summaryBadge)
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 6) {
                Image(systemName: coordinator.state.effectiveTimeZone != nil ? "clock.badge.checkmark" : "clock")
                    .font(.system(size: 11))
                    .foregroundStyle(coordinator.state.effectiveTimeZone != nil ? Color.accentColor : Color.secondary)
                if let tz = coordinator.state.effectiveTimeZone {
                    Text("客户端时区：\(TimezoneAlignmentResolver.formatDisplaySummary(for: tz))")
                        .font(.system(size: 11.5, design: .monospaced))
                        .foregroundStyle(.secondary)
                } else {
                    Text("客户端时区：跟随本机系统 (\(TimezoneAlignmentResolver.realMachineSystemTimeZoneIdentifier()))")
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(10)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    // MARK: - 4. 三路通道与目标真实链路明细

    private var channelBreakdownCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("多路出口一致性校验")
                .font(.system(size: 11.5, weight: .medium))
                .foregroundStyle(.secondary)

            if let httpSnap = coordinator.state.httpSnapshot {
                probeRow(
                    title: "HTTP 出口",
                    ip: httpSnap.ip,
                    badge: nil,
                    latency: httpSnap.latencyMs,
                    passed: httpSnap.passed,
                    missing: httpSnap.ip == nil
                )
            }

            if let stunSnap = coordinator.state.stunSnapshot {
                probeRow(
                    title: "UDP STUN",
                    ip: stunSnap.ip,
                    badge: nil,
                    latency: stunSnap.latencyMs,
                    passed: stunSnap.passed,
                    missing: stunSnap.ip == nil
                )
            }

            ForEach(coordinator.state.targetSnapshots) { tSnap in
                probeRow(
                    title: shortTargetTitle(tSnap.targetName),
                    ip: tSnap.ip,
                    badge: tSnap.countryCode,
                    latency: tSnap.latencyMs,
                    passed: tSnap.passed,
                    missing: tSnap.ip == nil
                )
            }

            if coordinator.state.targetSnapshots.isEmpty && coordinator.state.verdict.shouldBlockDomains {
                HStack(spacing: 6) {
                    Image(systemName: "lock.fill")
                        .font(.system(size: 10.5))
                        .foregroundStyle(.secondary)
                    Text("目标域名当前处于底层封锁态，待代理恢复后自动复核真实链路")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                }
                .padding(.top, 2)
            }
        }
        .padding(10)
        .background(.quaternary.opacity(0.25), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    private func probeRow(
        title: String,
        ip: String?,
        badge: String?,
        latency: Int?,
        passed: Bool,
        missing: Bool
    ) -> some View {
        HStack(spacing: 6) {
            Image(systemName: !coordinator.config.protectionEnabled ? "minus.circle" : (missing ? "clock.badge.exclamationmark" : (passed ? "checkmark.circle.fill" : "xmark.octagon.fill")))
                .font(.system(size: 12))
                .foregroundStyle(!coordinator.config.protectionEnabled ? Color.secondary : (missing ? Color.orange : (passed ? Color.green : Color.red)))
                .accessibilityHidden(true)

            Text(title)
                .font(.system(size: 12))
                .lineLimit(1)

            Spacer(minLength: 4)

            if let badge {
                Text(badge)
                    .font(.system(size: 10.5, weight: .medium, design: .monospaced))
                    .foregroundStyle(.secondary)
            }

            Text(ip ?? "未返回")
                .font(.system(size: 11.5, design: .monospaced))
                .foregroundStyle(ip == nil ? .secondary : .primary)
                .lineLimit(1)

            if let ms = latency {
                Text("\(ms)ms")
                    .font(.system(size: 10.5, design: .monospaced))
                    .foregroundStyle(.tertiary)
                    .frame(width: 42, alignment: .trailing)
            }
        }
    }

    // MARK: - 5. 快捷检测模式切换与已守护应用概览

    private var quickModeAndTargetsBar: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("检测模式")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                Spacer()
                Picker("检测模式", selection: Binding(
                    get: { coordinator.config.exitCheckMode },
                    set: { mode in
                        coordinator.updateConfig { $0.exitCheckMode = mode }
                    }
                )) {
                    ForEach(ExitCheckMode.allCases) { mode in
                        Text(mode.shortTitle).tag(mode)
                    }
                }
                .labelsHidden()
                .pickerStyle(.menu)
                .controlSize(.small)
                .frame(width: 170)
            }

            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ForEach(coordinator.config.targets) { target in
                        Button {
                            coordinator.updateConfig { cfg in
                                if let idx = cfg.targets.firstIndex(where: { $0.id == target.id }) {
                                    cfg.targets[idx].isEnabled.toggle()
                                }
                            }
                        } label: {
                            HStack(spacing: 4) {
                                Image(systemName: target.isEnabled ? "checkmark.shield.fill" : "circle")
                                    .font(.system(size: 10.5))
                                    .foregroundStyle(target.isEnabled ? Color.accentColor : .secondary)
                                Text(shortTargetTitle(target.name))
                                    .font(.system(size: 11.5, weight: target.isEnabled ? .medium : .regular))
                            }
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(
                                target.isEnabled ? Color.accentColor.opacity(0.14) : Color.secondary.opacity(0.1),
                                in: Capsule()
                            )
                        }
                        .buttonStyle(.plain)
                        .help("点击切换是否守护 \(target.name)")
                    }
                }
            }

            let installedEnabledTargets = coordinator.config.enabledTargets.filter {
                ProcessEnforcer.resolveInstalledAppURL(for: $0) != nil
            }
            if !installedEnabledTargets.isEmpty && !coordinator.state.verdict.shouldBlockFreshLaunch {
                HStack(spacing: 6) {
                    Text("带时区启动")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                    Spacer()
                    ForEach(installedEnabledTargets) { target in
                        Button {
                            coordinator.launchGuardedAppAligned(target)
                        } label: {
                            Label(shortTargetTitle(target.name), systemImage: "play.fill")
                                .font(.system(size: 11, weight: .medium))
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.mini)
                        .help("以对齐时区 (\(coordinator.state.effectiveTimeZone ?? "系统默认")) 启动 \(target.name)")
                    }
                }
            }
        }
    }

    // MARK: - 6. 底部工具栏

    private var footerBar: some View {
        HStack {
            Button {
                openSettingsAction(.general)
            } label: {
                Label("设置…", systemImage: "gearshape")
                    .font(.system(size: 12))
            }
            .buttonStyle(.borderless)
            .keyboardShortcut(",", modifiers: .command)

            Spacer()

            Button {
                openSettingsAction(.logs)
            } label: {
                Label("拦截日志", systemImage: "list.bullet.rectangle")
                    .font(.system(size: 12))
            }
            .buttonStyle(.borderless)

            Spacer()

            Button {
                NSApplication.shared.terminate(nil)
            } label: {
                Text("退出")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.borderless)
            .help("退出菜单栏进程（已写入的系统封锁规则在重新放行前会继续保持保护）")
        }
    }

    private func shortTargetTitle(_ raw: String) -> String {
        if let paren = raw.firstIndex(of: "(") {
            return String(raw[..<paren]).trimmingCharacters(in: .whitespaces)
        }
        return raw
    }
}
