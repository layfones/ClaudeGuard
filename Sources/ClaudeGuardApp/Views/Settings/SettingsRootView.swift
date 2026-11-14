import SwiftUI
import ClaudeGuardCore

struct SettingsRootView: View {
    @Bindable var coordinator: GuardCoordinator
    var openSetupAction: () -> Void

    var body: some View {
        TabView(selection: $coordinator.selectedSettingsTab) {
            GeneralSettingsPane(coordinator: coordinator, openSetupAction: openSetupAction)
                .tabItem {
                    Label("通用与防线", systemImage: "shield.lefthalf.filled")
                }
                .tag(SettingsTab.general)

            PolicySettingsPane(coordinator: coordinator)
                .tabItem {
                    Label("白名单与策略", systemImage: "checklist.checked")
                }
                .tag(SettingsTab.policy)

            TargetsSettingsPane(coordinator: coordinator)
                .tabItem {
                    Label("守护应用", systemImage: "square.grid.2x2")
                }
                .tag(SettingsTab.targets)

            LogsAndResetPane(coordinator: coordinator)
                .tabItem {
                    Label("日志与卸载", systemImage: "clock.arrow.circlepath")
                }
                .tag(SettingsTab.logs)
        }
        .frame(minWidth: 660, idealWidth: 680, minHeight: 520, idealHeight: 560)
    }
}
