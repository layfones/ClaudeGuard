import SwiftUI
import ClaudeGuardCore

/// 「白名单」面板：放行条件、IP 白名单、允许地区、出口变化、时区与高级选项。
struct PolicySettingsPane: View {
    @Bindable var coordinator: GuardCoordinator

    @State private var showAddSheet = false
    @State private var customRegionInput: String = ""

    private let presetRegions = ["US", "JP", "SG", "TW", "KR", "GB", "DE", "CA", "AU", "NL"]

    private var currentExitIP: String? {
        guard let ip = coordinator.state.primaryIP, CIDRMatcher.isValidLiteralIP(ip) else { return nil }
        return CIDRMatcher.firstMatchingEntry(for: ip, in: coordinator.config.allowedIPs) == nil ? ip : nil
    }

    var body: some View {
        Form {
            Section {
                Picker("放行规则", selection: Binding(
                    get: { coordinator.config.admissionRuleMode },
                    set: { rule in coordinator.updateConfig { $0.admissionRuleMode = rule } }
                )) {
                    ForEach(AdmissionRuleMode.allCases) { rule in
                        Text(rule.displayTitle).tag(rule)
                    }
                }
                Picker("检测方式", selection: Binding(
                    get: { coordinator.config.exitCheckMode },
                    set: { mode in coordinator.updateConfig { $0.exitCheckMode = mode } }
                )) {
                    ForEach(ExitCheckMode.allCases) { mode in
                        Text(mode.displayTitle).tag(mode)
                    }
                }
            } header: {
                Text("放行条件")
            } footer: {
                Text(coordinator.config.exitCheckMode.displayFootnote).formFootnote()
            }

            Section {
                if coordinator.config.allowedIPs.isEmpty {
                    Text("还没有白名单。先打开 v2rayN，确认连上后，再把当前出口加入。")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(coordinator.config.allowedIPs) { entry in
                        WhitelistRow(entry: entry, coordinator: coordinator)
                    }
                }
                HStack {
                    Button {
                        showAddSheet = true
                    } label: {
                        Label("添加…", systemImage: "plus")
                    }
                    .buttonStyle(.borderless)
                    Spacer()
                    if let ip = currentExitIP {
                        Button("加入当前出口 \(ip)") {
                            let fallback = coordinator.state.primaryCountryCode.map { "\(RoutePresenter.regionName(for: $0))节点" } ?? "代理节点"
                            _ = coordinator.addAllowedIP(cidrOrIP: ip, label: fallback)
                        }
                        .buttonStyle(.link)
                    }
                }
            } header: {
                Text("IP 白名单")
            } footer: {
                Text("先确认 v2rayN 已连上，再把当前出口加入白名单。右键点按一条可以删除。").formFootnote()
            }

            if coordinator.config.admissionRuleMode != .ipOnly {
                Section {
                    ChipFlowLayout(spacing: 6) {
                        ForEach(regionOptions, id: \.self) { code in
                            let on = coordinator.config.normalizedAllowedRegions.contains(code)
                            GuardChip(title: "\(RoutePresenter.regionName(for: code)) \(code)", isOn: on) {
                                toggleRegion(code)
                            }
                        }
                    }
                    .padding(.vertical, 2)
                    HStack {
                        TextField("其他地区码", text: $customRegionInput, prompt: Text("例如 FR"))
                            .frame(width: 200)
                            .onSubmit(addCustomRegion)
                        Button("添加", action: addCustomRegion)
                            .disabled(!isValidRegionCode(customRegionInput))
                    }
                } header: {
                    Text("允许地区")
                } footer: {
                    Text("地区来自目标网站返回的真实链路。").formFootnote()
                }
            }

            Section {
                Toggle(isOn: Binding(
                    get: { coordinator.config.detectIPChange },
                    set: { enabled in coordinator.updateConfig { $0.detectIPChange = enabled } }
                )) {
                    Text("出口变化时暂停放行")
                    Text("即使跳到另一个白名单节点，也需要你确认一次。")
                }
                if coordinator.state.jumpLatched {
                    HStack {
                        Text("\(coordinator.state.jumpBeforeIP ?? "原出口") → \(coordinator.state.jumpAfterIP ?? "新出口")")
                            .monospacedDigit()
                        Spacer()
                        Button("信任新出口") {
                            coordinator.acknowledgeCurrentExitJump()
                        }
                    }
                }
            } header: {
                Text("出口变化")
            }

            timezoneSection

            Section {
                Toggle(isOn: Binding(
                    get: { coordinator.config.useCustomHTTPProxy },
                    set: { val in coordinator.updateConfig { $0.useCustomHTTPProxy = val } }
                )) {
                    Text("手动指定本地 HTTP 代理")
                    Text("默认跟随系统代理和 TUN。检测和终端里的 claude 都会使用它。")
                }
                if coordinator.config.useCustomHTTPProxy {
                    HStack {
                        TextField("代理地址", text: Binding(
                            get: { coordinator.config.customHTTPProxyURL },
                            set: { url in coordinator.updateConfig({ $0.customHTTPProxyURL = url }, triggerCheck: false) }
                        ), prompt: Text("http://127.0.0.1:10808"))
                        .monospacedDigit()
                        Button("应用") { coordinator.triggerRecheck() }
                    }
                }
            } header: {
                Text("高级")
            }
        }
        .formStyle(.grouped)
        .sheet(isPresented: $showAddSheet) {
            AddWhitelistSheet(coordinator: coordinator, suggestedIP: coordinator.state.primaryIP)
        }
    }

    @ViewBuilder
    private var timezoneSection: some View {
        Section {
            Toggle(isOn: Binding(
                get: { coordinator.config.timezoneAlignmentEnabled },
                set: { enabled in coordinator.updateConfig { $0.timezoneAlignmentEnabled = enabled } }
            )) {
                Text("按出口地区设置客户端时区")
                Text("只影响受保护的应用，Mac 的系统时区保持不变。")
            }

            if coordinator.config.timezoneAlignmentEnabled {
                Picker("时区", selection: Binding(
                    get: { coordinator.config.timezoneAlignmentMode },
                    set: { mode in coordinator.updateConfig { $0.timezoneAlignmentMode = mode } }
                )) {
                    Text("自动（跟随出口）").tag(TimezoneAlignmentMode.autoFromExit)
                    Text("手动指定").tag(TimezoneAlignmentMode.manual)
                }

                if coordinator.config.timezoneAlignmentMode == .manual {
                    Picker("指定时区", selection: Binding(
                        get: { coordinator.config.manualTimeZoneIdentifier },
                        set: { tz in coordinator.updateConfig { $0.manualTimeZoneIdentifier = tz } }
                    )) {
                        ForEach(TimezoneAlignmentResolver.commonTimeZones, id: \.id) { item in
                            Text(item.label).tag(item.id)
                        }
                        if !TimezoneAlignmentResolver.commonTimeZones.contains(where: { $0.id == coordinator.config.manualTimeZoneIdentifier }) {
                            Text(coordinator.config.manualTimeZoneIdentifier).tag(coordinator.config.manualTimeZoneIdentifier)
                        }
                    }
                    TextField("IANA 时区", text: Binding(
                        get: { coordinator.config.manualTimeZoneIdentifier },
                        set: { raw in coordinator.updateConfig({ $0.manualTimeZoneIdentifier = raw }, triggerCheck: false) }
                    ), prompt: Text("America/Los_Angeles"))
                    .onSubmit { coordinator.triggerRecheck() }
                    if !TimezoneAlignmentResolver.isValidTimeZoneIdentifier(coordinator.config.manualTimeZoneIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)) {
                        Text("找不到这个时区。请使用 America/Los_Angeles、Asia/Seoul 这样的名称。")
                            .font(.subheadline)
                            .foregroundStyle(Color.guardBlock)
                    }
                }

                LabeledContent("当前生效") {
                    if let tz = coordinator.state.effectiveTimeZone {
                        Text(StatusDetailPresenter.timeZoneSummary(tz))
                    } else {
                        Text("跟随本机（\(TimezoneAlignmentResolver.realMachineSystemTimeZoneIdentifier())）")
                    }
                }

                Toggle(isOn: Binding(
                    get: { coordinator.config.relaunchDockAppsWithTimezone },
                    set: { val in coordinator.updateConfig({ $0.relaunchDockAppsWithTimezone = val }, triggerCheck: false) }
                )) {
                    Text("从 Dock 打开时也应用时区")
                    Text("直接点 Dock 图标打开受保护的应用时，ClaudeGuard 会按对应时区重新打开它。")
                }
            }
        } header: {
            Text("时区")
        }
    }

    private var regionOptions: [String] {
        let custom = coordinator.config.normalizedAllowedRegions.filter { !presetRegions.contains($0) }.sorted()
        return presetRegions + custom
    }

    private func isValidRegionCode(_ raw: String) -> Bool {
        let code = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return code.count == 2 && code.allSatisfy(\.isLetter)
    }

    private func addCustomRegion() {
        let code = customRegionInput.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard isValidRegionCode(code) else { return }
        if !coordinator.config.normalizedAllowedRegions.contains(code) {
            toggleRegion(code)
        }
        customRegionInput = ""
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

/// 白名单的一行：备注（可直接改） · 当前出口标记 · IP · 开关。
private struct WhitelistRow: View {
    let entry: AllowedIPEntry
    @Bindable var coordinator: GuardCoordinator
    @State private var hovering = false

    private var isCurrentExit: Bool {
        guard entry.isEnabled, let live = coordinator.state.primaryIP else { return false }
        return CIDRMatcher.matches(ip: live, rule: entry.cidrOrIP)
    }

    var body: some View {
        HStack(spacing: 10) {
            TextField("备注", text: Binding(
                get: { entry.label },
                set: { newLabel in
                    coordinator.updateConfig({ cfg in
                        if let idx = cfg.allowedIPs.firstIndex(where: { $0.id == entry.id }) {
                            cfg.allowedIPs[idx].label = newLabel
                        }
                    }, triggerCheck: false)
                }
            ), prompt: Text("添加备注"))
            .labelsHidden()
            .textFieldStyle(.plain)
            .foregroundStyle(entry.isEnabled ? .primary : .secondary)
            .frame(maxWidth: 180, alignment: .leading)

            if isCurrentExit {
                HStack(spacing: 4) {
                    Circle().fill(Color.guardPass).frame(width: 6, height: 6)
                    Text("当前出口")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
            }

            Spacer(minLength: 8)

            if hovering {
                Button(role: .destructive) {
                    remove()
                } label: {
                    Image(systemName: "minus.circle")
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
                .help("删除这条白名单")
                .accessibilityLabel("删除 \(entry.cidrOrIP)")
            }

            Text(entry.cidrOrIP)
                .monospacedDigit()
                .foregroundStyle(.secondary)
                .textSelection(.enabled)

            Toggle("启用 \(entry.cidrOrIP)", isOn: Binding(
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
            .toggleStyle(.switch)
            .controlSize(.small)
        }
        .onHover { hovering = $0 }
        .contextMenu {
            Button("删除", role: .destructive, action: remove)
        }
    }

    private func remove() {
        coordinator.updateConfig { cfg in
            cfg.allowedIPs.removeAll { $0.id == entry.id }
        }
    }
}

/// 添加白名单（IP 或网段 + 备注）。
private struct AddWhitelistSheet: View {
    @Bindable var coordinator: GuardCoordinator
    var suggestedIP: String?
    @Environment(\.dismiss) private var dismiss

    @State private var ipOrCIDR = ""
    @State private var remark = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("添加白名单")
                .font(.headline)
            Form {
                TextField("IP 或网段", text: $ipOrCIDR, prompt: Text("203.0.113.10 或 203.0.113.0/24"))
                    .monospacedDigit()
                TextField("备注", text: $remark, prompt: Text("例如：洛杉矶主力"))
                if let error {
                    Text(error)
                        .font(.subheadline)
                        .foregroundStyle(Color.guardBlock)
                }
            }
            .formStyle(.grouped)
            .scrollDisabled(true)

            HStack {
                if let ip = suggestedIP, ipOrCIDR.isEmpty {
                    Button("填入当前出口") { ipOrCIDR = ip }
                        .buttonStyle(.link)
                }
                Spacer()
                Button("取消", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("添加", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(ipOrCIDR.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(20)
        .frame(width: 420)
    }

    private func submit() {
        let trimmed = ipOrCIDR.trimmingCharacters(in: .whitespacesAndNewlines)
        guard CIDRMatcher.isValidIPOrCIDR(trimmed) else {
            error = "请输入有效的 IPv4、IPv6 地址或网段，例如 203.0.113.10 或 203.0.113.0/24。"
            return
        }
        if coordinator.addAllowedIP(cidrOrIP: trimmed, label: remark.trimmingCharacters(in: .whitespacesAndNewlines)) {
            dismiss()
        }
    }
}

// MARK: - 设置中的简短说明文字

extension AdmissionRuleMode {
    var displayTitle: String {
        switch self {
        case .ipOnly: return "只看 IP 白名单"
        case .ipOrRegion: return "IP 白名单或允许地区"
        case .ipAndRegion: return "IP 白名单且在允许地区"
        }
    }
}

extension ExitCheckMode {
    var displayTitle: String {
        switch self {
        case .all: return "HTTP、UDP 与目标网站"
        case .httpAndTrace: return "HTTP 与目标网站"
        case .stunAndTrace: return "UDP 与目标网站"
        }
    }

    var displayFootnote: String {
        switch self {
        case .all: return "适合 v2rayN 的 TUN 模式：三条线路都要符合规则才放行。"
        case .httpAndTrace: return "适合只开系统代理、UDP 直连的情况：不检查 UDP。"
        case .stunAndTrace: return "用 UDP 快速检查，并核对目标网站的真实链路。"
        }
    }
}
