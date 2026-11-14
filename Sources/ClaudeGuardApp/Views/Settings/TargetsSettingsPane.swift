import SwiftUI
import AppKit
import UniformTypeIdentifiers
import ClaudeGuardCore

struct TargetsSettingsPane: View {
    @Bindable var coordinator: GuardCoordinator

    @State private var showCustomTargetSheet = false
    @State private var draftAppName = ""
    @State private var draftBundleID = ""
    @State private var draftAppPath = ""
    @State private var draftDomainsText = ""
    @State private var draftTraceURL = ""

    var body: some View {
        Form {
            Section {
                ForEach(coordinator.config.targets) { target in
                    targetRow(target)
                }
            } header: {
                Text("受保护的 AI 客户端列表")
            } footer: {
                Text("已启用的客户端在出口未通过检查时：1) 相关域名被写入 /etc/hosts 沉洞（Anthropic 专属 IP 段同时写入 pf 内核防火墙）；2) 从 Dock、聚焦搜索或访达点击启动时毫秒级自动拦截；3) 运行中途代理掉线出现裸连 IP 时立即强行关闭进程。")
            }

            Section {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("守护其他 macOS 桌面应用")
                            .font(.body)
                        Text("从 /Applications 选择任意 .app，自动识别 Bundle ID 并配置专属域名与探测链路。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button {
                        pickApplicationFromFinder()
                    } label: {
                        Label("从「应用程序」选择添加…", systemImage: "plus.app")
                    }
                }
            } header: {
                Text("自定义扩展")
            }
        }
        .formStyle(.grouped)
        .sheet(isPresented: $showCustomTargetSheet) {
            customTargetSheet
        }
    }

    private func targetRow(_ target: GuardedTarget) -> some View {
        let installedAppPath = target.defaultAppPaths.first { FileManager.default.fileExists(atPath: $0) }

        return HStack(alignment: .center, spacing: 12) {
            appIconView(installedPath: installedAppPath)
                .frame(width: 34, height: 34)

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(target.name)
                        .font(.system(size: 13.5, weight: .semibold))

                    Text(installedAppPath != nil ? "本机已安装" : "未安装")
                        .font(.system(size: 10.5, weight: .medium))
                        .foregroundStyle(installedAppPath != nil ? .green : .secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1.5)
                        .background(
                            (installedAppPath != nil ? Color.green : Color.secondary).opacity(0.12),
                            in: Capsule()
                        )

                    if !target.dedicatedPFCIDRs.isEmpty {
                        Text("含 PF 内核封禁")
                            .font(.system(size: 10.5, weight: .medium))
                            .foregroundStyle(.blue)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1.5)
                            .background(Color.blue.opacity(0.12), in: Capsule())
                    }
                }

                Text(target.subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                HStack(spacing: 10) {
                    Label("封锁域名 \(target.expandedBlockedDomains.count) 个", systemImage: "network.slash")
                    if let trace = target.traceURL {
                        Label(trace.replacingOccurrences(of: "https://", with: ""), systemImage: "waveform.path.ecg")
                    }
                }
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.tertiary)
            }

            Spacer()

            if !target.isBuiltIn {
                Button(role: .destructive) {
                    coordinator.updateConfig { cfg in
                        cfg.targets.removeAll { $0.id == target.id }
                    }
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .help("删除此自定义守护应用")
            }

            Toggle("守护 \(target.name)", isOn: Binding(
                get: { target.isEnabled },
                set: { enabled in
                    coordinator.updateConfig { cfg in
                        if let idx = cfg.targets.firstIndex(where: { $0.id == target.id }) {
                            cfg.targets[idx].isEnabled = enabled
                        }
                    }
                }
            ))
            .labelsHidden()
            .toggleStyle(.switch)
            .controlSize(.small)
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private func appIconView(installedPath: String?) -> some View {
        if let path = installedPath {
            Image(nsImage: NSWorkspace.shared.icon(forFile: path))
                .resizable()
                .interpolation(.high)
        } else {
            Image(systemName: "app.dashed")
                .font(.system(size: 24))
                .foregroundStyle(.secondary)
        }
    }

    private var customTargetSheet: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("添加自定义守护应用")
                .font(.headline)

            Form {
                TextField("应用名称", text: $draftAppName)
                TextField("Bundle Identifier", text: $draftBundleID)
                    .font(.system(.body, design: .monospaced))
                TextField("需要封锁的根域名（逗号分隔，如 perplexity.ai, x.ai）", text: $draftDomainsText)
                    .font(.system(.body, design: .monospaced))
                TextField("可选真实链路探测 URL（如 https://x.ai/cdn-cgi/trace）", text: $draftTraceURL)
                    .font(.system(.body, design: .monospaced))
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("取消") {
                    showCustomTargetSheet = false
                }
                .keyboardShortcut(.cancelAction)

                Button("保存并启用守护") {
                    saveCustomTarget()
                }
                .buttonStyle(.borderedProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(draftAppName.trimmingCharacters(in: .whitespaces).isEmpty || draftBundleID.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(18)
        .frame(width: 480, height: 340)
    }

    private func pickApplicationFromFinder() {
        let panel = NSOpenPanel()
        panel.title = "选择要加入出口门禁守护的应用"
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.allowedContentTypes = [.applicationBundle]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false

        if panel.runModal() == .OK, let appURL = panel.url {
            let bundle = Bundle(url: appURL)
            draftAppPath = appURL.path
            draftBundleID = bundle?.bundleIdentifier ?? ""
            draftAppName = (bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
                ?? (bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String)
                ?? appURL.deletingPathExtension().lastPathComponent
            draftDomainsText = ""
            draftTraceURL = ""
            showCustomTargetSheet = true
        }
    }

    private func saveCustomTarget() {
        let domains = draftDomainsText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .filter { NetworkBlockStaging.isValidStagedDomain($0) }

        let trace = draftTraceURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let appFolderName = URL(fileURLWithPath: draftAppPath).lastPathComponent

        let custom = GuardedTarget(
            id: "custom-\(UUID().uuidString.prefix(8))",
            name: draftAppName.trimmingCharacters(in: .whitespacesAndNewlines),
            subtitle: "自定义守护应用 (\(draftBundleID))",
            isBuiltIn: false,
            isEnabled: true,
            bundleIDPrefixes: [draftBundleID.trimmingCharacters(in: .whitespacesAndNewlines)],
            processPathKeywords: appFolderName.isEmpty ? [] : ["/\(appFolderName)/Contents/"],
            defaultAppPaths: draftAppPath.isEmpty ? [] : [draftAppPath],
            traceURL: trace.isEmpty ? nil : trace,
            blockedApexDomains: domains
        )

        coordinator.updateConfig { cfg in
            cfg.targets.append(custom)
        }
        showCustomTargetSheet = false
    }
}
