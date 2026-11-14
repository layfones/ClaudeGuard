// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ClaudeGuard",
    defaultLocalization: "zh-Hans",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "ClaudeGuardCore", targets: ["ClaudeGuardCore"]),
        .executable(name: "ClaudeGuard", targets: ["ClaudeGuardApp"]),
        .executable(name: "claudeguard-cli", targets: ["ClaudeGuardCLI"]),
        .executable(name: "claudeguard-helper", targets: ["ClaudeGuardHelper"])
    ],
    targets: [
        .target(
            name: "ClaudeGuardCore",
            path: "Sources/ClaudeGuardCore",
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedFramework("Network"),
                .linkedFramework("SystemConfiguration"),
                .linkedFramework("ServiceManagement")
            ]
        ),
        .executableTarget(
            name: "ClaudeGuardApp",
            dependencies: ["ClaudeGuardCore"],
            path: "Sources/ClaudeGuardApp",
            linkerSettings: [
                .linkedFramework("SwiftUI"),
                .linkedFramework("AppKit"),
                .linkedFramework("UserNotifications")
            ]
        ),
        .executableTarget(
            name: "ClaudeGuardCLI",
            dependencies: ["ClaudeGuardCore"],
            path: "Sources/ClaudeGuardCLI"
        ),
        .executableTarget(
            name: "ClaudeGuardHelper",
            path: "Sources/ClaudeGuardHelper",
            cSettings: [
                .unsafeFlags(["-O2", "-Wall", "-Wextra"])
            ]
        ),
        .testTarget(
            name: "ClaudeGuardCoreTests",
            dependencies: ["ClaudeGuardCore"],
            path: "Tests/ClaudeGuardCoreTests"
        )
    ]
)
