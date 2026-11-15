import AppKit
import SwiftUI
import ClaudeGuardCore

extension SettingsTab {
    var title: String {
        switch self {
        case .general: return "通用"
        case .policy: return "白名单"
        case .targets: return "应用"
        case .logs: return "记录"
        }
    }

    var symbol: String {
        switch self {
        case .general: return "gearshape"
        case .policy: return "checkmark.shield"
        case .targets: return "square.grid.2x2"
        case .logs: return "list.bullet.rectangle"
        }
    }

    /// 各面板高度不同，窗口随面板切换自动调整（HIG：设置窗口适应当前面板大小）
    var paneSize: CGSize {
        switch self {
        case .general: return CGSize(width: 620, height: 560)
        case .policy: return CGSize(width: 620, height: 660)
        case .targets: return CGSize(width: 620, height: 500)
        case .logs: return CGSize(width: 620, height: 560)
        }
    }
}

/// 原生设置窗口：工具栏切换面板（macOS 26 起工具栏为 Liquid Glass），
/// 窗口标题跟随当前面板，记住上次查看的面板。
@MainActor
final class SettingsTabController: NSTabViewController {
    private static let lastPaneKey = "settings.lastViewedPane"

    static var lastViewedPane: SettingsTab? {
        UserDefaults.standard.string(forKey: lastPaneKey).flatMap(SettingsTab.init(rawValue:))
    }

    private let coordinator: GuardCoordinator

    init(coordinator: GuardCoordinator, openSetupAction: @escaping () -> Void) {
        self.coordinator = coordinator
        super.init(nibName: nil, bundle: nil)
        tabStyle = .toolbar
        transitionOptions = [.crossfade, .allowUserInteraction]

        for tab in SettingsTab.allCases {
            let host = NSHostingController(rootView: Self.pane(for: tab, coordinator: coordinator, openSetupAction: openSetupAction))
            host.sizingOptions = [.preferredContentSize]
            host.title = tab.title
            let item = NSTabViewItem(viewController: host)
            item.identifier = tab.rawValue
            item.label = tab.title
            item.image = NSImage(systemSymbolName: tab.symbol, accessibilityDescription: tab.title)
            addTabViewItem(item)
        }
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    func select(_ tab: SettingsTab) {
        if let idx = SettingsTab.allCases.firstIndex(of: tab) {
            selectedTabViewItemIndex = idx
        }
    }

    override func tabView(_ tabView: NSTabView, didSelect tabViewItem: NSTabViewItem?) {
        super.tabView(tabView, didSelect: tabViewItem)
        guard let raw = tabViewItem?.identifier as? String, let tab = SettingsTab(rawValue: raw) else { return }
        coordinator.selectedSettingsTab = tab
        UserDefaults.standard.set(tab.rawValue, forKey: Self.lastPaneKey)
        view.window?.title = tab.title
    }

    private static func pane(for tab: SettingsTab, coordinator: GuardCoordinator, openSetupAction: @escaping () -> Void) -> AnyView {
        let size = tab.paneSize
        let content: AnyView
        switch tab {
        case .general:
            content = AnyView(GeneralSettingsPane(coordinator: coordinator, openSetupAction: openSetupAction))
        case .policy:
            content = AnyView(PolicySettingsPane(coordinator: coordinator))
        case .targets:
            content = AnyView(TargetsSettingsPane(coordinator: coordinator))
        case .logs:
            content = AnyView(LogsAndResetPane(coordinator: coordinator))
        }
        return AnyView(content.frame(width: size.width, height: size.height))
    }
}
