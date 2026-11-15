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
                    Toggle("只看拦截", isOn: $onlyInterceptEvents)
                        .toggleStyle(.checkbox)

                    Spacer()

                    Button("清空") {
                        coordinator.clearEvents()
                    }
                    .controlSize(.small)
                    .disabled(coordinator.recentEvents.isEmpty)
                }

                if filteredEvents.isEmpty {
                    Text(onlyInterceptEvents ? "还没有拦截记录。" : "还没有记录。")
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
                    .frame(height: 280)
                }
            } header: {
                Text("拦截记录")
            }

            Section {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("解除全部封锁")
                        Text("暂停守护，并移除 ClaudeGuard 写入的域名封锁和防火墙规则。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("解除封锁") {
                        coordinator.emergencyUnblock()
                    }
                }

                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("卸载 ClaudeGuard")
                        Text("还原所有网络设置和 claude 命令，移除后台服务，然后退出。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button(role: .destructive) {
                        showUninstallConfirmation = true
                    } label: {
                        Text("卸载…")
                    }
                }
            } header: {
                Text("恢复")
            }
        }
        .formStyle(.grouped)
        .onAppear {
            coordinator.refreshEvents()
        }
        .alert("要卸载 ClaudeGuard 吗？", isPresented: $showUninstallConfirmation) {
            Button("取消", role: .cancel) {}
            Button("卸载", role: .destructive) {
                coordinator.uninstallAndQuit()
            }
        } message: {
            Text("需要输入一次管理员密码。网络设置和 claude 命令会恢复到安装前的样子。")
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
                        .font(.subheadline)
                        .monospacedDigit()
                        .foregroundStyle(.secondary)

                    Text(ev.kind.label)
                        .font(.subheadline.weight(.medium))

                    if let ip = ev.detectedIP {
                        Text(ip)
                            .font(.subheadline)
                            .monospacedDigit()
                            .foregroundStyle(.secondary)
                    }
                }

                Text(ev.message)
                    .font(.body)
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
        case .timezoneAlignedLaunch:
            return "clock.badge.checkmark.fill"
        case .systemIPv6Toggled:
            return "network.badge.shield.half.filled"
        case .emergencyUnblocked:
            return "lock.open.fill"
        default:
            return "info.circle.fill"
        }
    }

    private func colorForEvent(_ kind: GuardEventKind) -> Color {
        switch kind {
        case .appLaunchIntercepted, .runningAppTerminated, .cliSessionBlocked:
            return .guardBlock
        case .ipJumpLatched, .probeWarning:
            return .guardHold
        case .helperInstalled, .ipJumpAcknowledged, .timezoneAlignedLaunch:
            return .guardPass
        default:
            return .secondary
        }
    }
}
