import AppKit
import SwiftUI
import ClaudeGuardCore

/// 遵循 Apple HIG `alerts.md` 的拦截告警弹窗：
/// - 杜绝连续重复刷屏弹窗；
/// - 针对“忘记开启 v2rayN”场景直接提供「启动 v2rayN」一键恢复主按钮；
/// - 针对“IP 发生跳变”场景直接提供「信任当前新出口」主按钮。
@MainActor
public enum InterceptAlertPresenter {
    private static var isPresenting = false

    public static func present(
        title: String,
        reason: String,
        state: SharedGuardState,
        coordinator: GuardCoordinator
    ) {
        guard !isPresenting else { return }
        isPresenting = true

        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = title

        var detailLines: [String] = [reason]
        if let ip = state.primaryIP {
            let cc = state.primaryCountryCode.map { " (\($0))" } ?? ""
            detailLines.append("当前检测出口：\(ip)\(cc)")
        }
        detailLines.append("代理环境：\(state.proxyEnvironment.summaryBadge)")
        if state.helperInstalled {
            detailLines.append("系统底层防线已保持封锁，未产生直连请求泄漏。")
        }
        alert.informativeText = detailLines.joined(separator: "\n")

        enum ButtonAction {
            case launchV2rayN
            case acknowledgeJump
            case openSettings
            case dismiss
        }

        var actions: [ButtonAction] = []
        if state.proxyEnvironment.isV2rayNInstalled && !state.proxyEnvironment.isV2rayNRunning {
            alert.addButton(withTitle: "启动 v2rayN")
            actions.append(.launchV2rayN)
            alert.addButton(withTitle: "打开设置…")
            actions.append(.openSettings)
            alert.addButton(withTitle: "知道了")
            actions.append(.dismiss)
        } else if state.jumpLatched {
            alert.addButton(withTitle: "信任当前新出口")
            actions.append(.acknowledgeJump)
            alert.addButton(withTitle: "打开设置…")
            actions.append(.openSettings)
            alert.addButton(withTitle: "保持拦截")
            actions.append(.dismiss)
        } else {
            alert.addButton(withTitle: "知道了")
            actions.append(.dismiss)
            alert.addButton(withTitle: "打开设置…")
            actions.append(.openSettings)
        }

        alert.window.level = .floating
        let response = alert.runModal()
        isPresenting = false

        let idx = response.rawValue - NSApplication.ModalResponse.alertFirstButtonReturn.rawValue
        guard idx >= 0 && idx < actions.count else { return }

        switch actions[idx] {
        case .launchV2rayN:
            coordinator.launchV2rayN()
        case .acknowledgeJump:
            coordinator.acknowledgeCurrentExitJump()
        case .openSettings:
            coordinator.selectedSettingsTab = .policy
            AppWindowRouter.showSettingsWindow(coordinator: coordinator)
        case .dismiss:
            break
        }
    }
}

/// 在 `LSUIElement` 菜单栏应用模式下 100% 可靠地管理并前置「设置窗口」与「首次配置向导窗口」。
@MainActor
enum AppWindowRouter {
    private static var settingsWindow: NSWindow?
    private static var setupWindow: NSWindow?

    static func showSettingsWindow(coordinator: GuardCoordinator) {
        NSApp.activate(ignoringOtherApps: true)
        if let existing = settingsWindow {
            existing.makeKeyAndOrderFront(nil)
            return
        }
        let root = SettingsRootView(coordinator: coordinator) {
            showSetupWindow(coordinator: coordinator)
        }
        let controller = NSHostingController(rootView: root)
        let win = NSWindow(contentViewController: controller)
        win.title = "ClaudeGuard 设置"
        win.styleMask = [.titled, .closable, .resizable]
        win.setContentSize(NSSize(width: 680, height: 560))
        win.center()
        win.isReleasedWhenClosed = false
        settingsWindow = win
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
        let win = NSWindow(contentViewController: controller)
        win.title = "ClaudeGuard 初始防线配置"
        win.styleMask = [.titled, .closable]
        win.setContentSize(NSSize(width: 580, height: 500))
        win.center()
        win.isReleasedWhenClosed = false
        setupWindow = win
        win.makeKeyAndOrderFront(nil)
    }
}
