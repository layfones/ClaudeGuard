import SwiftUI
import AppKit
import ClaudeGuardCore

/// 首次引导：三步完成网络防线安装、确认代理出口、开始守护。
/// 同一时间只有当前步骤的按钮是主按钮（HIG：每个视图一个主操作）。
struct SetupGuideView: View {
    @Bindable var coordinator: GuardCoordinator
    var onClose: (() -> Void)? = nil
    @Environment(\.dismiss) private var dismiss

    @State private var nodeRemark: String = ""

    private enum Step: Int {
        case helper = 1, exit, start
    }

    private var hasWhitelistedAnyIP: Bool {
        !coordinator.config.enabledAllowedIPs.isEmpty || !coordinator.config.normalizedAllowedRegions.isEmpty
    }

    private var activeStep: Step {
        if !coordinator.state.helperInstalled { return .helper }
        if !hasWhitelistedAnyIP { return .exit }
        return .start
    }

    private var detectedIP: String? {
        coordinator.state.httpSnapshot?.ip ?? coordinator.state.primaryIP
    }

    private var stunMismatchIP: String? {
        guard coordinator.config.exitCheckMode.includesSTUN,
              let hIP = coordinator.state.httpSnapshot?.ip,
              let sIP = coordinator.state.stunSnapshot?.ip,
              hIP != sIP else {
            return nil
        }
        return sIP
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            hero

            GuardGroup {
                stepRow(.helper, title: "安装网络防线", subtitle: coordinator.state.helperInstalled
                        ? "已安装。之后封锁和解封都不再需要输入密码。"
                        : "出口不对时，用它封锁受保护应用的网络连接。需要输入一次管理员密码。") {
                    if !coordinator.state.helperInstalled {
                        actionButton("安装网络防线…", step: .helper) {
                            coordinator.installHelperWithPrompt()
                        }
                    }
                }
                Divider().padding(.leading, 56)
                stepRow(.exit, title: "确认代理出口", subtitle: hasWhitelistedAnyIP
                        ? "已加入白名单：\(whitelistSummary)"
                        : "先确认 v2rayN 已连上。下面是 ClaudeGuard 刚刚检测到的出口：") {
                    if !hasWhitelistedAnyIP {
                        exitStepContent
                    }
                }
                Divider().padding(.leading, 56)
                stepRow(.start, title: "开始守护",
                        subtitle: "以后照常从 Dock 打开 Claude。出口不对时，ClaudeGuard 会拦下它并告诉你原因。") {
                    EmptyView()
                }
            }

            if let msg = coordinator.lastActionMessage {
                Label(msg, systemImage: coordinator.lastActionIsError ? "exclamationmark.circle" : "checkmark.circle")
                    .font(.subheadline)
                    .foregroundStyle(coordinator.lastActionIsError ? Color.guardBlock : .secondary)
            }

            HStack {
                Button("稍后设置") {
                    close()
                }
                .buttonStyle(.link)

                Spacer()

                if activeStep == .start {
                    Button("开始守护") {
                        coordinator.completeOnboarding()
                        close()
                    }
                    .guardProminentButton()
                    .controlSize(.large)
                    .keyboardShortcut(.defaultAction)
                } else {
                    Button("开始守护") {}
                        .controlSize(.large)
                        .disabled(true)
                        .help("完成前两步后可用")
                }
            }
        }
        .padding(.horizontal, 36)
        .padding(.top, 44)
        .padding(.bottom, 22)
        .frame(width: 600)
    }

    // MARK: - 头部

    private var hero: some View {
        HStack(spacing: 18) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .interpolation(.high)
                .frame(width: 80, height: 80)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 6) {
                Text("出口不对，Claude 就不开")
                    .font(.system(size: 26, weight: .bold))
                Text("ClaudeGuard 会在 Claude 联网之前检查你的网络出口。完成下面三步，就可以像平常一样从 Dock 打开 Claude。")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: - 第 2 步：确认出口

    @ViewBuilder
    private var exitStepContent: some View {
        VStack(alignment: .leading, spacing: 12) {
            RouteView(route: RoutePresenter.make(state: coordinator.state, config: coordinator.config), width: 440)

            if coordinator.state.proxyEnvironment.isV2rayNInstalled && !coordinator.state.proxyEnvironment.isV2rayNRunning {
                HStack(spacing: 8) {
                    Text("v2rayN 没有运行，这很可能是本机真实 IP。")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    Spacer(minLength: 0)
                    Button("启动 v2rayN") { coordinator.launchV2rayN() }
                        .controlSize(.small)
                }
            }

            if let mismatch = stunMismatchIP {
                VStack(alignment: .leading, spacing: 6) {
                    Text("UDP 出口（\(mismatch)）和网页出口不一致，UDP 可能绕开了代理。")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 8) {
                        if mismatch.contains(":") {
                            Button("关闭公网 IPv6") {
                                coordinator.toggleSystemPublicIPv6(disable: true)
                            }
                            .disabled(coordinator.isSwitchingIPv6)
                        }
                        Button("只检查网页出口") {
                            coordinator.updateConfig { $0.exitCheckMode = .httpAndTrace }
                        }
                    }
                    .controlSize(.small)
                }
            }

            HStack(spacing: 8) {
                Text("备注")
                    .foregroundStyle(.secondary)
                TextField("例如：洛杉矶主力", text: $nodeRemark)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(addDetectedExit)
                actionButton("加入白名单", step: .exit, action: addDetectedExit)
                    .disabled(detectedIP == nil)
            }

            Button("重新检测") { coordinator.triggerRecheck() }
                .buttonStyle(.link)
                .font(.subheadline)
        }
        .padding(.top, 4)
    }

    private var whitelistSummary: String {
        let ips = coordinator.config.enabledAllowedIPs.map { $0.label.isEmpty ? $0.cidrOrIP : "\($0.cidrOrIP)（\($0.label)）" }
        let regions = coordinator.config.normalizedAllowedRegions.sorted().map(RoutePresenter.regionName(for:))
        return (ips + regions).joined(separator: "、")
    }

    private func addDetectedExit() {
        guard let ip = detectedIP else { return }
        let fallback = coordinator.state.primaryCountryCode.map { "\(RoutePresenter.regionName(for: $0))节点" } ?? "代理节点"
        let remark = nodeRemark.trimmingCharacters(in: .whitespacesAndNewlines)
        if coordinator.addAllowedIP(cidrOrIP: ip, label: remark.isEmpty ? fallback : remark) {
            nodeRemark = ""
        }
    }

    // MARK: - 步骤行

    @ViewBuilder
    private func actionButton(_ title: String, step: Step, action: @escaping () -> Void) -> some View {
        if activeStep == step {
            Button(title, action: action)
                .guardProminentButton()
        } else {
            Button(title, action: action)
        }
    }

    private func stepRow<Content: View>(
        _ step: Step,
        title: String,
        subtitle: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        let done = step.rawValue < activeStep.rawValue
        let active = step == activeStep
        return HStack(alignment: .top, spacing: 14) {
            stepIndicator(step, done: done, active: active)
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text(title)
                        .font(.headline)
                        .foregroundStyle(done || active ? .primary : .secondary)
                    Spacer()
                    if done {
                        Text("已完成")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                content()
            }
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 16)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("第 \(step.rawValue) 步：\(title)\(done ? "，已完成" : "")")
    }

    private func stepIndicator(_ step: Step, done: Bool, active: Bool) -> some View {
        ZStack {
            if done {
                Circle().fill(Color.guardPass.opacity(0.15))
                Image(systemName: "checkmark")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundStyle(Color.guardPass)
            } else {
                Circle().strokeBorder(active ? Color.primary : Color.secondary.opacity(0.5), lineWidth: 1.5)
                Text("\(step.rawValue)")
                    .font(.headline)
                    .foregroundStyle(active ? .primary : .secondary)
            }
        }
        .frame(width: 24, height: 24)
        .accessibilityHidden(true)
    }

    private func close() {
        onClose?()
        dismiss()
    }
}
