import SwiftUI
import ClaudeGuardCore

/// 首次启动向导：三步在图形界面完成特权助手授权、当前代理节点加入白名单与启用保护，全程无需打开终端敲命令。
struct SetupGuideView: View {
    @Bindable var coordinator: GuardCoordinator
    var onClose: (() -> Void)? = nil
    @Environment(\.dismiss) private var dismiss

    @State private var nodeRemark: String = "v2rayN 主力节点"
    @State private var manualIPInput: String = ""

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

    private var hasWhitelistedAnyIP: Bool {
        !coordinator.config.enabledAllowedIPs.isEmpty || !coordinator.config.normalizedAllowedRegions.isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            // 头部品牌与一句话价值说明
            HStack(spacing: 14) {
                ZStack {
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(Color.accentColor.opacity(0.15))
                        .frame(width: 52, height: 52)
                    Image(systemName: "checkmark.shield.fill")
                        .font(.system(size: 28, weight: .semibold))
                        .foregroundStyle(Color.accentColor)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text("欢迎使用 ClaudeGuard 原生客户端")
                        .font(.title3.weight(.semibold))
                    Text("只需 2 步完成初始化，即可防止忘记开启 v2rayN 或节点掉线时直连暴露真实 IP。")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }

            Divider()

            // 步骤 1：系统级特权助手授权
            stepCard(
                number: "1",
                title: "启用内核级零泄漏防线（仅需授权一次）",
                completed: coordinator.state.helperInstalled
            ) {
                Text("安装轻量级 LaunchDaemon 网络助手，用于在代理未就绪时自动锁定 /etc/hosts 与 macOS pf 子锚点防火墙。日常运行不再弹窗索要密码。")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                HStack {
                    if coordinator.state.helperInstalled {
                        Label("系统级网络助手已就绪", systemImage: "checkmark.circle.fill")
                            .font(.subheadline.weight(.medium))
                            .foregroundStyle(.green)
                    } else {
                        Button("授权安装特权网络助手…") {
                            coordinator.installHelperWithPrompt()
                        }
                        .buttonStyle(.borderedProminent)
                    }
                    Spacer()
                }
            }

            // 步骤 2：确认代理已开启并将当前出口加入白名单
            stepCard(
                number: "2",
                title: "开启 v2rayN 并将你的代理出口 IP 加入白名单",
                completed: hasWhitelistedAnyIP
            ) {
                HStack(spacing: 10) {
                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 6) {
                            Text("当前检测到的出口：")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            Text(detectedIP ?? "正在检测…")
                                .font(.system(size: 13.5, weight: .semibold, design: .monospaced))
                            if let cc = coordinator.state.primaryCountryCode {
                                Text(cc)
                                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1)
                                    .background(.quaternary, in: Capsule())
                            }
                        }
                        Text("代理状态：\(coordinator.state.proxyEnvironment.summaryBadge)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    if coordinator.state.proxyEnvironment.isV2rayNInstalled && !coordinator.state.proxyEnvironment.isV2rayNRunning {
                        Button("启动 v2rayN") {
                            coordinator.launchV2rayN()
                        }
                        .controlSize(.small)
                    }

                    Button("重新检测") {
                        coordinator.triggerRecheck()
                    }
                    .controlSize(.small)
                }

                HStack(spacing: 8) {
                    TextField(
                        detectedIP ?? "输入代理出口 IP",
                        text: Binding(
                            get: { manualIPInput.isEmpty ? (detectedIP ?? "") : manualIPInput },
                            set: { manualIPInput = $0 }
                        )
                    )
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))

                    TextField("节点备注", text: $nodeRemark)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 150)

                    Button("加入白名单") {
                        let ipToUse = manualIPInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                            ? (detectedIP ?? "")
                            : manualIPInput
                        if coordinator.addAllowedIP(cidrOrIP: ipToUse, label: nodeRemark) {
                            manualIPInput = ""
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled((manualIPInput.isEmpty && detectedIP == nil))
                }

                if let mismatchSTUN = stunMismatchIP {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(alignment: .top, spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                            VStack(alignment: .leading, spacing: 2) {
                                Text("检测到 UDP/IPv6 出口不一致：STUN 返回 \(mismatchSTUN)")
                                    .font(.caption.weight(.semibold))
                                Text("说明本机运营商公网 IPv6 绕过了 v2rayN IPv4 隧道。推荐直接一键关闭系统公网 IPv6（保留 AirDrop 本地链路），或切换为「HTTP + 目标链路」检测模式。")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        HStack(spacing: 8) {
                            Button {
                                coordinator.toggleSystemPublicIPv6(disable: true)
                            } label: {
                                Label("一键关闭系统公网 IPv6（推荐）", systemImage: "network.slash")
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.small)
                            .disabled(coordinator.isSwitchingIPv6)

                            Button("改用 HTTP+目标链路模式") {
                                coordinator.updateConfig { $0.exitCheckMode = .httpAndTrace }
                            }
                            .controlSize(.small)
                        }
                    }
                    .padding(8)
                    .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                }

                if hasWhitelistedAnyIP {
                    let listSummary = coordinator.config.enabledAllowedIPs
                        .map { "\($0.cidrOrIP) (\($0.label))" }
                        .joined(separator: "、")
                    Label("已添加白名单：\(listSummary)", systemImage: "checkmark.circle.fill")
                        .font(.caption)
                        .foregroundStyle(.green)
                        .lineLimit(2)
                }
            }

            if let msg = coordinator.lastActionMessage {
                Text(msg)
                    .font(.caption)
                    .foregroundStyle(coordinator.lastActionIsError ? .red : .secondary)
            }

            Spacer(minLength: 4)

            // 底部完成按钮
            HStack {
                Text("推荐将 v2rayN 设为「TUN 模式」以获得完整的 TCP + UDP 全流量防护。")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Spacer()

                Button("稍后在设置中配置") {
                    onClose?()
                    dismiss()
                }

                Button("立即开启守护") {
                    coordinator.completeOnboarding()
                    onClose?()
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!hasWhitelistedAnyIP)
            }
        }
        .padding(22)
        .frame(width: 580)
        .frame(minHeight: 520)
    }

    private func stepCard<Content: View>(
        number: String,
        title: String,
        completed: Bool,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                ZStack {
                    Circle()
                        .fill(completed ? Color.green : Color.accentColor)
                        .frame(width: 22, height: 22)
                    if completed {
                        Image(systemName: "checkmark")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundStyle(.white)
                    } else {
                        Text(number)
                            .font(.system(size: 12, weight: .bold, design: .rounded))
                            .foregroundStyle(.white)
                    }
                }
                Text(title)
                    .font(.system(size: 14, weight: .semibold))
            }

            content()
                .padding(.leading, 30)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.32), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}
