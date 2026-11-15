import SwiftUI
import ClaudeGuardCore

/// 「通用」面板：网络防线、运行方式与 Claude 相关选项。
struct GeneralSettingsPane: View {
    @Bindable var coordinator: GuardCoordinator
    var openSetupAction: () -> Void

    private let intervalOptions: [Double] = [1, 2, 3, 5, 10, 15, 30]

    var body: some View {
        Form {
            Section {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Circle()
                                .fill(coordinator.state.helperInstalled ? Color.guardPass : Color.guardHold)
                                .frame(width: 7, height: 7)
                            Text(coordinator.state.helperInstalled ? "网络防线已安装" : "网络防线未安装")
                        }
                        Text(coordinator.state.helperInstalled
                             ? "出口不对时，封锁受保护应用的域名和连接。"
                             : "安装后才能在出口不对时封锁网络。需要输入一次管理员密码。")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Button(coordinator.state.helperInstalled ? "重新安装…" : "安装…") {
                        coordinator.installHelperWithPrompt()
                    }
                }
                .accessibilityElement(children: .combine)

                Toggle(isOn: Binding(
                    get: { coordinator.systemIPv6Status.isPublicIPv6DisabledOnAll },
                    set: { disable in coordinator.toggleSystemPublicIPv6(disable: disable) }
                )) {
                    Text("关闭系统公网 IPv6")
                    Text(coordinator.systemIPv6Status.summaryText)
                }
                .disabled(coordinator.isSwitchingIPv6 || coordinator.systemIPv6Status.services.isEmpty)

                HStack {
                    Button("打开初始设置…", action: openSetupAction)
                    Spacer()
                    Button("检查并修复") { coordinator.runDoctorRepair() }
                        .help("重新挂载终端 claude 命令的保护，并重新下发网络规则")
                }
            } header: {
                Text("网络防线")
            }

            Section {
                Toggle("启用守护", isOn: Binding(
                    get: { coordinator.config.protectionEnabled },
                    set: { coordinator.toggleProtection($0) }
                ))

                Toggle("登录时启动 ClaudeGuard", isOn: Binding(
                    get: { coordinator.config.launchAtLogin },
                    set: { enabled in
                        PrivilegedInstaller.setLaunchAtLogin(enabled: enabled, paths: coordinator.paths)
                        coordinator.updateConfig({ $0.launchAtLogin = enabled }, triggerCheck: false)
                    }
                ))

                Toggle(isOn: Binding(
                    get: { coordinator.config.showInterceptAlert },
                    set: { val in coordinator.updateConfig({ $0.showInterceptAlert = val }, triggerCheck: false) }
                )) {
                    Text("拦截时显示提示")
                    Text("关闭后仍会拦截，只在菜单栏图标上显示。")
                }

                Picker("后台检查间隔", selection: Binding(
                    get: { coordinator.config.clampedPollInterval },
                    set: { interval in coordinator.updateConfig({ $0.pollIntervalSeconds = interval }, triggerCheck: false) }
                )) {
                    ForEach(intervalOptions, id: \.self) { sec in
                        Text(sec == 3 ? "\(Int(sec)) 秒（推荐）" : "\(Int(sec)) 秒").tag(sec)
                    }
                }
            } header: {
                Text("运行")
            } footer: {
                Text("网络、代理或 TUN 发生变化，以及 Mac 从睡眠中唤醒时，会立即重新检查。").formFootnote()
            }

            Section {
                Toggle(isOn: Binding(
                    get: { coordinator.config.protectClaudeCLI },
                    set: { enabled in
                        coordinator.updateConfig({ $0.protectClaudeCLI = enabled }, triggerCheck: false)
                        coordinator.cliStatus = CLIHookManager.syncHooks(
                            protectCLI: enabled,
                            configuredRealCLI: coordinator.config.realClaudeCLIPath,
                            paths: coordinator.paths
                        )
                    }
                )) {
                    Text("保护终端里的 claude 命令")
                    Text(cliSubtitleText)
                }

                Toggle(isOn: Binding(
                    get: { coordinator.config.blockClaudeAutoUpdates },
                    set: { enabled in coordinator.updateConfig { $0.blockClaudeAutoUpdates = enabled } }
                )) {
                    Text("禁止 Claude 自动更新")
                    Text("锁定更新目录并屏蔽更新服务器，终端里的 claude 也不会自动更新。")
                }
            } header: {
                Text("Claude")
            }
        }
        .formStyle(.grouped)
    }

    private var cliSubtitleText: String {
        if let real = coordinator.cliStatus.realCLIPath {
            return "已找到 \(real)，每分钟检查一次，防止升级后失效。"
        }
        return "这台 Mac 没有单独安装 claude 命令。Claude 桌面端里的 Claude Code 已经受到保护。"
    }
}
