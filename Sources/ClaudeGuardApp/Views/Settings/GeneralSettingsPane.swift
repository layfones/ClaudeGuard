import SwiftUI
import ClaudeGuardCore

struct GeneralSettingsPane: View {
    @Bindable var coordinator: GuardCoordinator
    var openSetupAction: () -> Void

    private let intervalOptions: [Double] = [1, 2, 3, 5, 10, 15, 30]

    var body: some View {
        Form {
            Section {
                HStack(spacing: 12) {
                    Image(systemName: coordinator.state.helperInstalled ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .font(.system(size: 24))
                        .foregroundStyle(coordinator.state.helperInstalled ? .green : .orange)
                        .accessibilityHidden(true)

                    VStack(alignment: .leading, spacing: 3) {
                        Text(coordinator.state.helperInstalled ? "系统级特权网络防线已就绪" : "尚未安装系统级特权网络防线")
                            .font(.headline)
                        Text(
                            coordinator.state.helperInstalled
                                ? "已启用 /etc/hosts 域名沉洞与 macOS pf 子锚点 (com.apple/claudeguard) 内核包过滤，可在应用启动前彻底阻断直连握手与 QUIC 流量。"
                                : "授权安装一次后，后台无需重复输入密码即可在代理断开时提前锁死目标域名与防火墙连接。"
                        )
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    }

                    Spacer()

                    Button(coordinator.state.helperInstalled ? "重新部署" : "授权安装…") {
                        coordinator.installHelperWithPrompt()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(coordinator.state.helperInstalled ? .secondary : .accentColor)
                }
                .padding(.vertical, 4)

                HStack {
                    Text("防线完整性巡检")
                    Spacer()
                    Button("打开初始配置向导…") {
                        openSetupAction()
                    }
                    Button("立即自检并修复钩子") {
                        coordinator.runDoctorRepair()
                    }
                }

                Toggle(isOn: Binding(
                    get: { coordinator.systemIPv6Status.isPublicIPv6DisabledOnAll },
                    set: { disable in
                        coordinator.toggleSystemPublicIPv6(disable: disable)
                    }
                )) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("一键关闭系统公网 IPv6（设为仅本地链接，不影响 AirDrop）")
                        Text(coordinator.systemIPv6Status.summaryText)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .disabled(coordinator.isSwitchingIPv6 || coordinator.systemIPv6Status.services.isEmpty)
            } header: {
                Text("内核级零泄漏防线")
            }

            Section {
                Toggle("启用全局出口守护", isOn: Binding(
                    get: { coordinator.config.protectionEnabled },
                    set: { coordinator.toggleProtection($0) }
                ))

                Toggle("登录 macOS 时自动在菜单栏启动", isOn: Binding(
                    get: { coordinator.config.launchAtLogin },
                    set: { enabled in
                        PrivilegedInstaller.setLaunchAtLogin(enabled: enabled, paths: coordinator.paths)
                        coordinator.updateConfig({ $0.launchAtLogin = enabled }, triggerCheck: false)
                    }
                ))

                Toggle("拦截启动或熔断关停时弹出桌面警告框", isOn: Binding(
                    get: { coordinator.config.showInterceptAlert },
                    set: { val in
                        coordinator.updateConfig({ $0.showInterceptAlert = val }, triggerCheck: false)
                    }
                ))

                Picker("后台自动复查间隔", selection: Binding(
                    get: { coordinator.config.clampedPollInterval },
                    set: { interval in
                        coordinator.updateConfig({ $0.pollIntervalSeconds = interval }, triggerCheck: false)
                    }
                )) {
                    ForEach(intervalOptions, id: \.self) { sec in
                        Text(sec == 3 ? "\(Int(sec)) 秒（推荐）" : "\(Int(sec)) 秒").tag(sec)
                    }
                }
            } header: {
                Text("运行与提醒")
            } footer: {
                Text("除定时轮询外，当 v2rayN 开关、Wi-Fi 切换、TUN 路由变化或合盖唤醒时，系统事件会在约 0.3 秒内立即触发重检。")
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
                    VStack(alignment: .leading, spacing: 2) {
                        Text("守护终端独立 claude 命令行会话")
                        Text(cliSubtitleText)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                Toggle(isOn: Binding(
                    get: { coordinator.config.blockClaudeAutoUpdates },
                    set: { enabled in
                        coordinator.updateConfig { $0.blockClaudeAutoUpdates = enabled }
                    }
                )) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("禁止 Claude 自动更新")
                        Text("同时锁定 ShipIt 更新缓存目录 (uchg)、屏蔽更新域名并为 CLI 注入禁用更新环境变量。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("Claude 专属防护增强")
            }
        }
        .formStyle(.grouped)
    }

    private var cliSubtitleText: String {
        if let real = coordinator.cliStatus.realCLIPath {
            return "已识别真实二进制：\(real)（每 60 秒自动巡检防重装覆盖）"
        }
        return "本机暂未安装独立 claude CLI；Claude Desktop 内嵌的 Code 模式已由桌面进程防线直接保护。"
    }
}
