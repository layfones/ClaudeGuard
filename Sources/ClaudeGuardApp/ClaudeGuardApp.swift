import SwiftUI
import AppKit
import ClaudeGuardCore

public final class AppLifecycleDelegate: NSObject, NSApplicationDelegate {
    public func applicationDidFinishLaunching(_ notification: Notification) {
        // 单实例保护：若已有 ClaudeGuard 实例在后台运行，当前重复启动自动退出
        let myPID = ProcessInfo.processInfo.processIdentifier
        let bundleID = Bundle.main.bundleIdentifier ?? "com.claudeguard.app"
        let duplicates = NSWorkspace.shared.runningApplications.filter {
            $0.processIdentifier != myPID && ($0.bundleIdentifier == bundleID || $0.localizedName == "ClaudeGuard")
        }
        if !duplicates.isEmpty {
            NSApplication.shared.terminate(nil)
            return
        }

        NSApplication.shared.setActivationPolicy(.accessory)
        MainActor.assumeIsolated {
            let coord = GuardCoordinator.shared
            coord.startIfNeeded()
            if coord.showSetupWindow {
                AppWindowRouter.showSetupWindow(coordinator: coord)
            }
        }
    }
}

@main
struct ClaudeGuardApp: App {
    @NSApplicationDelegateAdaptor(AppLifecycleDelegate.self) private var appDelegate
    @State private var coordinator = GuardCoordinator.shared

    var body: some Scene {
        MenuBarExtra {
            StatusPopoverView(
                coordinator: coordinator,
                openSetupAction: {
                    AppWindowRouter.showSetupWindow(coordinator: coordinator)
                },
                openSettingsAction: { tab in
                    coordinator.selectedSettingsTab = tab
                    AppWindowRouter.showSettingsWindow(coordinator: coordinator)
                }
            )
        } label: {
            Image(systemName: menuBarSymbolName)
                .symbolRenderingMode(.monochrome)
                .accessibilityLabel("ClaudeGuard：\(coordinator.state.verdict.title)")
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsRootView(coordinator: coordinator, openSetupAction: {
                AppWindowRouter.showSetupWindow(coordinator: coordinator)
            })
        }
    }

    private var menuBarSymbolName: String {
        if !coordinator.config.onboardingCompleted || !coordinator.state.helperInstalled {
            return "exclamationmark.shield"
        }
        return coordinator.state.verdict.sfSymbolName
    }
}
