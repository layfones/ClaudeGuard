import AppKit
import SwiftUI
import ClaudeGuardCore

/// 拦截提示（NSAlert，macOS 26 起由系统绘制 Liquid Glass 外观）。
/// 遵循 HIG `alerts.md`：
/// - 标题直接说明发生了什么，正文只给原因，不解释按钮；
/// - 默认按钮放在尾侧，取消类按钮在前侧；不使用警告符号；
/// - Dock 启动可能反复触发，提供「不再提醒」抑制选项（拦截照常进行）。
@MainActor
public enum InterceptAlertPresenter {
    public enum Kind {
        /// 从 Dock / 访达 / 聚焦启动受保护应用时被拦下
        case launchBlocked(appName: String)
        /// 运行中出口变化，已关闭受保护应用
        case runningAppsClosed(names: [String])
    }

    private enum ButtonAction {
        case launchV2rayN
        case acknowledgeJump
        case recheckRouteLeak
        case openWhitelistSettings
        case dismiss
    }

    private static var isPresenting = false

    public static func present(_ kind: Kind, state: SharedGuardState, coordinator: GuardCoordinator) {
        guard !isPresenting else { return }
        isPresenting = true
        defer { isPresenting = false }

        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .informational

        switch kind {
        case .launchBlocked(let appName):
            alert.messageText = "已阻止 \(appName) 启动"
        case .runningAppsClosed(let names):
            alert.messageText = "出口异常，已关闭 \(names.joined(separator: "、"))"
        }

        let proxy = state.proxyEnvironment
        var actions: [ButtonAction] = []
        // NSAlert 的第一个按钮是默认按钮，显示在最右侧
        if proxy.isV2rayNInstalled && !proxy.isV2rayNRunning {
            if let ip = state.primaryIP {
                alert.informativeText = "当前出口 \(ip) 是本机真实 IP，v2rayN 似乎没有运行。"
            } else {
                alert.informativeText = "v2rayN 似乎没有运行，暂时无法确认出口。"
            }
            alert.addButton(withTitle: "启动 v2rayN")
            actions.append(.launchV2rayN)
            alert.addButton(withTitle: "取消")
            actions.append(.dismiss)
        } else if state.jumpLatched {
            let before = state.jumpBeforeIP ?? "原出口"
            let after = state.jumpAfterIP ?? state.primaryIP ?? "新出口"
            alert.informativeText = "出口从 \(before) 变成了 \(after)。确认是你自己切换了节点，再放行。"
            alert.addButton(withTitle: "信任新出口")
            actions.append(.acknowledgeJump)
            alert.addButton(withTitle: "保持拦截")
            actions.append(.dismiss)
        } else {
            let verdict = VerdictPresenter.make(
                state: state,
                config: coordinator.config,
                context: .init(
                    helperInstalled: state.helperInstalled,
                    publicIPv6Disabled: coordinator.systemIPv6Status.isPublicIPv6DisabledOnAll,
                    installedTargetIDs: []
                )
            )
            alert.informativeText = verdict.message
            if verdict.action == .recheckRouteLeak {
                alert.addButton(withTitle: "重新检查")
                actions.append(.recheckRouteLeak)
                alert.addButton(withTitle: "取消")
                actions.append(.dismiss)
            } else {
                alert.addButton(withTitle: "好")
                actions.append(.dismiss)
                alert.addButton(withTitle: "打开白名单设置…")
                actions.append(.openWhitelistSettings)
            }
        }

        alert.showsSuppressionButton = true
        alert.suppressionButton?.title = "不再提醒（仍会拦截，并在菜单栏显示）"
        alert.window.level = .floating

        let response = alert.runModal()

        if alert.suppressionButton?.state == .on {
            coordinator.updateConfig({ $0.showInterceptAlert = false }, triggerCheck: false)
        }

        let idx = response.rawValue - NSApplication.ModalResponse.alertFirstButtonReturn.rawValue
        guard idx >= 0 && idx < actions.count else { return }

        switch actions[idx] {
        case .launchV2rayN:
            coordinator.launchV2rayN()
        case .acknowledgeJump, .recheckRouteLeak:
            coordinator.acknowledgeCurrentExitJump()
        case .openWhitelistSettings:
            AppWindowRouter.showSettingsWindow(coordinator: coordinator, pane: .policy)
        case .dismiss:
            break
        }
    }
}

/// 在 `LSUIElement` 菜单栏应用模式下可靠地管理并前置「设置窗口」与「首次引导窗口」。
@MainActor
enum AppWindowRouter {
    private static var settingsWindow: NSWindow?
    private static var settingsTabs: SettingsTabController?
    private static var setupWindow: NSWindow?

    /// 打开设置窗口；未指定面板时恢复上次查看的面板（HIG `settings.md`）。
    static func showSettingsWindow(coordinator: GuardCoordinator, pane: SettingsTab? = nil) {
        NSApp.activate(ignoringOtherApps: true)
        let target = pane ?? SettingsTabController.lastViewedPane ?? coordinator.selectedSettingsTab

        if let existing = settingsWindow, let tabs = settingsTabs {
            tabs.select(target)
            existing.makeKeyAndOrderFront(nil)
            return
        }

        let tabs = SettingsTabController(coordinator: coordinator) {
            showSetupWindow(coordinator: coordinator)
        }
        tabs.select(target)

        let win = NSWindow(contentViewController: tabs)
        // 设置窗口：最小化与缩放按钮置灰，工具栏不可自定义
        win.styleMask = [.titled, .closable]
        win.toolbarStyle = .preference
        win.isReleasedWhenClosed = false
        win.center()
        settingsWindow = win
        settingsTabs = tabs
        win.makeKeyAndOrderFront(nil)
    }

    static func showSetupWindow(coordinator: GuardCoordinator) {
        NSApp.activate(ignoringOtherApps: true)
        if let existing = setupWindow {
            existing.makeKeyAndOrderFront(nil)
            return
        }
        let root = SetupGuideView(coordinator: coordinator) {
            setupWindow?.close()
        }
        let controller = NSHostingController(rootView: root)
        controller.sizingOptions = [.preferredContentSize]
        let win = NSWindow(contentViewController: controller)
        win.title = "欢迎使用 ClaudeGuard"
        win.titlebarAppearsTransparent = true
        win.titleVisibility = .hidden
        win.styleMask = [.titled, .closable, .fullSizeContentView]
        win.isMovableByWindowBackground = true
        win.center()
        win.isReleasedWhenClosed = false
        setupWindow = win
        win.makeKeyAndOrderFront(nil)
    }
}
