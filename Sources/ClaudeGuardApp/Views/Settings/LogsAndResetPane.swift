import SwiftUI
import ClaudeGuardCore

struct LogsAndResetPane: View {
    @Bindable var coordinator: GuardCoordinator

    @State private var onlyInterceptEvents = false
    @State private var showUninstallConfirmation = false

    private static let dateFormatter: DateFormatter = {
        let df = DateFormatter()
        df.dateFormat = "MM-dd HH:mm:ss"
        return df
    }()

    private var filteredEvents: [GuardEvent] {
        if !onlyInterceptEvents {
            return coordinator.recentEvents
        }
        return coordinator.recentEvents.filter {
            switch $0.kind {
            case .appLaunchIntercepted, .runningAppTerminated, .cliSessionBlocked, .ipJumpLatched:
                return true
            default:
                return false
            }
        }
    }

    var body: some View {
        Form {
            Section {
                HStack {
                    Toggle("仅看拦截与熔断记录", isOn: $onlyInterceptEvents)
                        .toggleStyle(.checkbox)

                    Spacer()

                    Button("刷新") {
                        coordinator.refreshEvents()
                    }
                    .controlSize(.small)

                    Button("清空日志") {
                        coordinator.clearEvents()
                    }
                    .controlSize(.small)
                    .disabled(coordinator.recentEvents.isEmpty)
                }

                if filteredEvents.isEmpty {
                    Text("暂无符合筛选条件的事件日志。")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                        .padding(.vertical, 24)
                } else {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 8) {
                            ForEach(filteredEvents) { ev in
                                eventRow(ev)
                                Divider()
                            }
                        }
                        .padding(.vertical, 4)
                    }
                    .frame(height: 240)
                }
            } header: {
                Text("安全拦截与状态变更时间线（最近 \(filteredEvents.count) 条）")
            }

            Section {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("紧急解除全部网络封锁")
                        Text("立即暂停防护，清除 /etc/hosts 中的受管段落、清空 pf 子锚点规则并解冻更新目录。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("紧急解封网络") {
                        coordinator.emergencyUnblock()
                    }
                }

                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("彻底无残留卸载 ClaudeGuard")
                            .foregroundStyle(.red)
                        Text("一键还原 /etc/hosts、释放 pf 防火墙锚点、恢复原版 claude 命令软链、移除开机自启与系统 LaunchDaemon 服务并退出。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button(role: .destructive) {
                        showUninstallConfirmation = true
                    } label: {
                        Text("彻底卸载并还原…")
                    }
                }
            } header: {
                Text("应急恢复与无残留卸载")
            }
        }
        .formStyle(.grouped)
        .onAppear {
            coordinator.refreshEvents()
        }
        .alert("确认彻底卸载 ClaudeGuard 并还原系统设置？", isPresented: $showUninstallConfirmation) {
            Button("取消", role: .cancel) {}
            Button("彻底卸载并退出", role: .destructive) {
                coordinator.uninstallAndQuit()
            }
        } message: {
            Text("将要求输入一次管理员密码以移除 /Library/LaunchDaemons/com.claudeguard.helper.plist，并完整恢复 /etc/hosts、pf 防火墙与 claude 命令行入口。")
        }
    }

    private func eventRow(_ ev: GuardEvent) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: iconForEvent(ev.kind))
                .foregroundStyle(colorForEvent(ev.kind))
                .frame(width: 16)
                .padding(.top, 2)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(Self.dateFormatter.string(from: ev.timestamp))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)

                    Text(ev.kind.label)
                        .font(.system(size: 10.5, weight: .semibold))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(colorForEvent(ev.kind).opacity(0.14), in: RoundedRectangle(cornerRadius: 4))

                    if let ip = ev.detectedIP {
                        Text(ip)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }

                Text(ev.message)
                    .font(.system(size: 12))
                    .foregroundStyle(.primary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func iconForEvent(_ kind: GuardEventKind) -> String {
        switch kind {
        case .appLaunchIntercepted, .runningAppTerminated, .cliSessionBlocked:
            return "xmark.shield.fill"
        case .ipJumpLatched:
            return "lock.trianglebadge.exclamationmark.fill"
        case .verdictChanged:
            return "arrow.left.arrow.right.circle.fill"
        case .helperInstalled, .ipJumpAcknowledged:
            return "checkmark.seal.fill"
        case .emergencyUnblocked:
            return "lock.open.fill"
        default:
            return "info.circle.fill"
        }
    }

    private func colorForEvent(_ kind: GuardEventKind) -> Color {
        switch kind {
        case .appLaunchIntercepted, .runningAppTerminated, .cliSessionBlocked:
            return .red
        case .ipJumpLatched, .probeWarning:
            return .orange
        case .helperInstalled, .ipJumpAcknowledged:
            return .green
        default:
            return .accentColor
        }
    }
}
