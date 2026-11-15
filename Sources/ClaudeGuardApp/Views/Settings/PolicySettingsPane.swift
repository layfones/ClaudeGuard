import SwiftUI
import ClaudeGuardCore

struct PolicySettingsPane: View {
    @Bindable var coordinator: GuardCoordinator

    @State private var newIPOrCIDR: String = ""
    @State private var newRemark: String = ""
    @State private var customRegionInput: String = ""
    @State private var validationError: String?

    private let presetRegions: [(code: String, label: String)] = [
        ("US", "🇺🇸 美国 US"),
        ("JP", "🇯🇵 日本 JP"),
        ("SG", "🇸🇬 新加坡 SG"),
        ("TW", "🇹🇼 台湾 TW"),
        ("KR", "🇰🇷 韩国 KR"),
        ("GB", "🇬🇧 英国 GB"),
        ("DE", "🇩🇪 德国 DE"),
        ("CA", "🇨🇦 加拿大 CA"),
        ("AU", "🇦🇺 澳大利亚 AU"),
        ("NL", "🇳🇱 荷兰 NL")
    ]

    var body: some View {
        Form {
            Section {
                Picker("出口检测通道", selection: Binding(
                    get: { coordinator.config.exitCheckMode },
                    set: { mode in
                        coordinator.updateConfig { $0.exitCheckMode = mode }
                    }
                )) {
                    ForEach(ExitCheckMode.allCases) { mode in
                        Text(mode.title).tag(mode)
                    }
                }

                Text(coordinator.config.exitCheckMode.subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Picker("放行判定条件", selection: Binding(
                    get: { coordinator.config.admissionRuleMode },
                    set: { rule in
                        coordinator.updateConfig { $0.admissionRuleMode = rule }
                    }
                )) {
                    ForEach(AdmissionRuleMode.allCases) { rule in
                        Text(rule.title).tag(rule)
                    }
                }
            } header: {
                Text("检测模式与准入规则")
            }

            Section {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        TextField("IP 或 CIDR（如 203.0.113.10 或 198.51.100.0/24）", text: $newIPOrCIDR)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))

                        TextField("节点备注（如：v2rayN 美西主力）", text: $newRemark)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 180)

                        if let liveIP = coordinator.state.primaryIP {
                            Button("填入当前 IP") {
                                newIPOrCIDR = liveIP
                                if newRemark.isEmpty, let cc = coordinator.state.primaryCountryCode {
                                    newRemark = "\(cc) 代理节点"
                                }
                                validationError = nil
                            }
                            .help("填入当前探测到的出口：\(liveIP)")
                        }

                        Button("添加") {
                            submitNewIPEntry()
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(newIPOrCIDR.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }

                    if let err = validationError {
                        Text(err)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }

                if coordinator.config.allowedIPs.isEmpty {
                    HStack {
                        Image(systemName: "shield.lefthalf.filled.trianglebadge.exclamationmark")
                            .foregroundStyle(.orange)
                        Text("当前白名单为空：在仅白名单模式下将默认拦截所有受保护客户端，请先开启 v2rayN 后添加你的节点出口 IP。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                } else {
                    ForEach(coordinator.config.allowedIPs) { entry in
                        whitelistRow(entry)
                    }
                }
            } header: {
                Text("IP / 网段白名单（\(coordinator.config.enabledAllowedIPs.count) 条启用中）")
            }

            if coordinator.config.admissionRuleMode != .ipOnly {
                Section {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 118), spacing: 8)], alignment: .leading, spacing: 8) {
                        ForEach(presetRegions, id: \.code) { item in
                            let selected = coordinator.config.normalizedAllowedRegions.contains(item.code)
                            Button {
                                toggleRegion(item.code)
                            } label: {
                                HStack(spacing: 4) {
                                    Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                                        .foregroundStyle(selected ? Color.accentColor : .secondary)
                                    Text(item.label)
                                        .font(.system(size: 12))
                                    Spacer(minLength: 0)
                                }
                                .padding(.horizontal, 8)
                                .padding(.vertical, 5)
                                .background(
                                    selected ? Color.accentColor.opacity(0.14) : Color.secondary.opacity(0.08),
                                    in: RoundedRectangle(cornerRadius: 7, style: .continuous)
                                )
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(.vertical, 4)

                    HStack(spacing: 8) {
                        TextField("其他两位 ISO 国家/地区码（如 FR、NL）", text: $customRegionInput)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 240)
                        Button("添加地区码") {
                            let code = customRegionInput.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
                            guard code.count == 2, code.allSatisfy(\.isLetter) else { return }
                            if !coordinator.config.normalizedAllowedRegions.contains(code) {
                                toggleRegion(code)
                            }
                            customRegionInput = ""
                        }
                        Spacer()
                        if !coordinator.config.normalizedAllowedRegions.isEmpty {
                            Text("已启用：\(coordinator.config.normalizedAllowedRegions.sorted().joined(separator: ", "))")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("允许的国家 / 地区码（基于目标 cdn-cgi/trace 真实链路识别）")
                }
            }

            Section {
                Picker("客户端时区策略", selection: Binding(
                    get: { coordinator.config.timezoneAlignmentMode },
                    set: { mode in
                        coordinator.updateConfig { $0.timezoneAlignmentMode = mode }
                    }
                )) {
                    ForEach(TimezoneAlignmentMode.allCases) { mode in
                        Text(mode.title).tag(mode)
                    }
                }

                HStack {
                    Text("当前生效状态")
                        .foregroundStyle(.secondary)
                    Spacer()
                    if let tz = coordinator.state.effectiveTimeZone {
                        Text("本机保持 \(TimezoneAlignmentResolver.realMachineSystemTimeZoneIdentifier())  →  客户端注入 \(TimezoneAlignmentResolver.formatDisplaySummary(for: tz))")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.green)
                    } else {
                        Text("沿用本机时区 \(TimezoneAlignmentResolver.realMachineSystemTimeZoneIdentifier())")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }

                if coordinator.config.timezoneAlignmentMode == .manual {
                    Picker("常用目标时区", selection: Binding(
                        get: { coordinator.config.manualTimeZoneIdentifier },
                        set: { tz in
                            coordinator.updateConfig { $0.manualTimeZoneIdentifier = tz }
                        }
                    )) {
                        ForEach(TimezoneAlignmentResolver.commonTimeZones, id: \.id) { item in
                            Text(item.label).tag(item.id)
                        }
                        if !TimezoneAlignmentResolver.commonTimeZones.contains(where: { $0.id == coordinator.config.manualTimeZoneIdentifier }) {
                            Text(coordinator.config.manualTimeZoneIdentifier).tag(coordinator.config.manualTimeZoneIdentifier)
                        }
                    }

                    HStack {
                        Text("自定义 IANA 时区")
                        TextField("例如 America/Los_Angeles 或 Asia/Seoul", text: Binding(
                            get: { coordinator.config.manualTimeZoneIdentifier },
                            set: { raw in
                                coordinator.updateConfig({ $0.manualTimeZoneIdentifier = raw }, triggerCheck: false)
                            }
                        ))
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))

                        Button("校验并应用") {
                            coordinator.triggerRecheck()
                        }
                    }

                    if !TimezoneAlignmentResolver.isValidTimeZoneIdentifier(coordinator.config.manualTimeZoneIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)) {
                        Text("无效的 IANA 时区名称，请使用形如 America/Los_Angeles、Asia/Seoul、Europe/London 的标准标识符。")
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }

                if coordinator.config.timezoneAlignmentMode != .disabled {
                    Toggle(isOn: Binding(
                        get: { coordinator.config.relaunchDockAppsWithTimezone },
                        set: { val in
                            coordinator.updateConfig({ $0.relaunchDockAppsWithTimezone = val }, triggerCheck: false)
                        }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("点击 Dock 栏启动受保护应用时自动重拉起并注入时区")
                            Text("开启后，即使直接点击 Dock 栏上的原版 Claude 或 ChatGPT 图标，ClaudeGuard 也会自动通过 LaunchServices 为其补齐进程级 TZ 时区，同时完全不修改 Mac 系统时间与微信/日历。")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text("进程级时区自动对齐（不修改整机系统时区）")
            }

            Section {
                Toggle(isOn: Binding(
                    get: { coordinator.config.detectIPChange },
                    set: { enabled in
                        coordinator.updateConfig { $0.detectIPChange = enabled }
                    }
                )) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("开启持久化 IP 跳变锁")
                        Text("记录首次合规基准 IP；一旦中途出口发生跳变（哪怕跳到了另一个白名单节点），也会立即锁死拦截，直到你手动点击「信任当前新出口」确认，防止短时间跨节点跳 IP 触发风控。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                if coordinator.state.jumpLatched {
                    HStack {
                        Label(
                            "当前处于跳变锁定：\(coordinator.state.jumpBeforeIP ?? "-") → \(coordinator.state.jumpAfterIP ?? "-")",
                            systemImage: "lock.trianglebadge.exclamationmark.fill"
                        )
                        .font(.caption)
                        .foregroundStyle(.orange)
                        Spacer()
                        Button("信任当前出口并解封") {
                            coordinator.acknowledgeCurrentExitJump()
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                    }
                }

                Toggle("手动指定探测与 CLI 使用的本地 HTTP 代理（默认自动跟随系统代理与 TUN）", isOn: Binding(
                    get: { coordinator.config.useCustomHTTPProxy },
                    set: { val in
                        coordinator.updateConfig { $0.useCustomHTTPProxy = val }
                    }
                ))

                if coordinator.config.useCustomHTTPProxy {
                    HStack {
                        Text("HTTP 代理地址")
                        TextField("例如 http://127.0.0.1:10808", text: Binding(
                            get: { coordinator.config.customHTTPProxyURL },
                            set: { url in
                                coordinator.updateConfig({ $0.customHTTPProxyURL = url }, triggerCheck: false)
                            }
                        ))
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))

                        Button("应用并重测") {
                            coordinator.triggerRecheck()
                        }
                    }
                }
            } header: {
                Text("防跳变锁与高级代理选项")
            }
        }
        .formStyle(.grouped)
    }

    private func whitelistRow(_ entry: AllowedIPEntry) -> some View {
        let isCurrentlyMatched: Bool = {
            guard entry.isEnabled, let live = coordinator.state.primaryIP else { return false }
            return CIDRMatcher.matches(ip: live, rule: entry.cidrOrIP)
        }()

        return HStack(spacing: 10) {
            Toggle("启用该规则", isOn: Binding(
                get: { entry.isEnabled },
                set: { val in
                    coordinator.updateConfig { cfg in
                        if let idx = cfg.allowedIPs.firstIndex(where: { $0.id == entry.id }) {
                            cfg.allowedIPs[idx].isEnabled = val
                        }
                    }
                }
            ))
            .labelsHidden()
            .toggleStyle(.checkbox)

            Text(entry.cidrOrIP)
                .font(.system(.body, design: .monospaced, weight: .medium))
                .foregroundStyle(entry.isEnabled ? .primary : .secondary)
                .frame(minWidth: 165, alignment: .leading)

            TextField("节点备注", text: Binding(
                get: { entry.label },
                set: { newLabel in
                    coordinator.updateConfig({ cfg in
                        if let idx = cfg.allowedIPs.firstIndex(where: { $0.id == entry.id }) {
                            cfg.allowedIPs[idx].label = newLabel
                        }
                    }, triggerCheck: false)
                }
            ))
            .textFieldStyle(.roundedBorder)
            .controlSize(.small)

            if isCurrentlyMatched {
                Text("当前命中")
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundStyle(.green)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(.green.opacity(0.14), in: Capsule())
            }

            Spacer()

            Button(role: .destructive) {
                coordinator.updateConfig { cfg in
                    cfg.allowedIPs.removeAll { $0.id == entry.id }
                }
            } label: {
                Image(systemName: "trash")
                    .foregroundStyle(.red.opacity(0.85))
            }
            .buttonStyle(.borderless)
            .help("移除此白名单规则")
            .accessibilityLabel("移除 \(entry.cidrOrIP)")
        }
    }

    private func submitNewIPEntry() {
        let trimmed = newIPOrCIDR.trimmingCharacters(in: .whitespacesAndNewlines)
        guard CIDRMatcher.isValidIPOrCIDR(trimmed) else {
            validationError = "请输入合法的 IPv4/IPv6 地址或 CIDR 网段（例如 203.0.113.10 或 203.0.113.0/24）。"
            return
        }
        validationError = nil
        if coordinator.addAllowedIP(
            cidrOrIP: trimmed,
            label: newRemark.trimmingCharacters(in: .whitespacesAndNewlines)
        ) {
            newIPOrCIDR = ""
            newRemark = ""
        }
    }

    private func toggleRegion(_ code: String) {
        coordinator.updateConfig { cfg in
            var set = cfg.normalizedAllowedRegions
            if set.contains(code) {
                set.remove(code)
            } else {
                set.insert(code)
            }
            cfg.allowedRegions = set.sorted()
        }
    }
}
