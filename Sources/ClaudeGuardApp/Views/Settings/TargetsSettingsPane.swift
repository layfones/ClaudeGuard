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
                Text("受保护的应用")
            } footer: {
                Text("出口不对时，ClaudeGuard 会封锁这些应用的域名，拦下从 Dock、访达或聚焦搜索的启动，并关闭正在运行的应用。").formFootnote()
            }

            Section {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("保护其他应用")
                        Text("从“应用程序”文件夹选一个 App，再填写它要封锁的域名。")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("添加应用…") {
                        pickApplicationFromFinder()
                    }
                }
            } header: {
                Text("其他应用")
            }
        }
        .formStyle(.grouped)
        .sheet(isPresented: $showCustomTargetSheet) {
            customTargetSheet
        }
    }

    private func targetRow(_ target: GuardedTarget) -> some View {
        let installedAppPath = target.defaultAppPaths.first { FileManager.default.fileExists(atPath: $0) }
        var details: [String] = [installedAppPath != nil ? "已安装" : "未安装"]
        details.append("封锁 \(target.expandedBlockedDomains.count) 个域名")
        if let trace = target.traceURL, let host = URL(string: trace)?.host {
            details.append("检测 \(host)")
        }

        return HStack(alignment: .center, spacing: 12) {
            appIconView(installedPath: installedAppPath)
                .frame(width: 32, height: 32)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                Text(VerdictPresenter.shortName(target.name))
                Text(details.joined(separator: " · "))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            if !target.isBuiltIn {
                Button(role: .destructive) {
                    coordinator.updateConfig { cfg in
                        cfg.targets.removeAll { $0.id == target.id }
                    }
                } label: {
                    Image(systemName: "minus.circle")
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
                .help("移除这个应用")
                .accessibilityLabel("移除 \(target.name)")
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
        .padding(.vertical, 2)
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
            Text("保护其他应用")
                .font(.headline)

            Form {
                TextField("名称", text: $draftAppName)
                TextField("Bundle Identifier", text: $draftBundleID)
                    .font(.system(.body, design: .monospaced))
                TextField("要封锁的域名", text: $draftDomainsText, prompt: Text("用逗号分隔，例如 perplexity.ai, x.ai"))
                    .font(.system(.body, design: .monospaced))
                TextField("检测地址（可选）", text: $draftTraceURL, prompt: Text("https://x.ai/cdn-cgi/trace"))
                    .font(.system(.body, design: .monospaced))
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("取消") {
                    showCustomTargetSheet = false
                }
                .keyboardShortcut(.cancelAction)

                Button("添加") {
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
        panel.title = "选择要保护的应用"
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
            subtitle: "自定义应用（\(draftBundleID)）",
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
