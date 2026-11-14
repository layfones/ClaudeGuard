import Foundation
import AppKit
import SystemConfiguration
import Darwin

/// 只读感知本机代理运行环境：检测 v2rayN 是否安装/运行、活跃的 TUN 虚拟网卡（排除仅 fe80:: 链路本地系统空壳 utun）与系统代理。
public enum ProxyEnvironmentDetector {
    public static let v2rayNBundleID = "2dust.v2rayN"
    public static let v2rayNDefaultPaths = [
        "/Applications/v2rayN.app",
        (NSHomeDirectory() as NSString).appendingPathComponent("Applications/v2rayN.app")
    ]

    public static func inspect() -> ProxyEnvironmentSnapshot {
        let installedPath = v2rayNDefaultPaths.first { FileManager.default.fileExists(atPath: $0) }
        let runningApps = NSWorkspace.shared.runningApplications
        let v2rayRunning = runningApps.contains { app in
            if app.bundleIdentifier == v2rayNBundleID { return true }
            let name = (app.localizedName ?? "").lowercased()
            return name == "v2rayn"
        }

        let activeTUNs = detectActiveTUNInterfaces()
        let sysProxy = readSystemHTTPProxy()

        return ProxyEnvironmentSnapshot(
            isV2rayNInstalled: installedPath != nil || v2rayRunning,
            isV2rayNRunning: v2rayRunning,
            v2rayNAppPath: installedPath,
            activeTUNInterfaces: activeTUNs,
            systemHTTPProxy: sysProxy
        )
    }

    /// 识别真正挂载了 IPv4 或非链路本地 IPv6 地址且处于 UP+RUNNING 的 `utun*` 隧道网卡
    /// （排除 macOS 系统常驻空闲的 `utun0/1/2` 仅含 `fe80::` 地址的虚拟口）。
    public static func detectActiveTUNInterfaces() -> [String] {
        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let firstAddr = ifaddrPtr else {
            return []
        }
        defer { freeifaddrs(ifaddrPtr) }

        var activeNames = Set<String>()
        var cursor: UnsafeMutablePointer<ifaddrs>? = firstAddr

        while let ifa = cursor?.pointee {
            defer { cursor = ifa.ifa_next }
            let name = String(cString: ifa.ifa_name)
            guard name.hasPrefix("utun") || name.hasPrefix("ppp") || name.hasPrefix("ipsec") else {
                continue
            }
            let flags = Int32(ifa.ifa_flags)
            guard (flags & IFF_UP) != 0, (flags & IFF_RUNNING) != 0 else {
                continue
            }
            guard let sa = ifa.ifa_addr else { continue }
            let family = Int32(sa.pointee.sa_family)

            if family == AF_INET {
                activeNames.insert(name)
            } else if family == AF_INET6 {
                let sin6 = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                var addr = sin6.sin6_addr
                let bytes = withUnsafeBytes(of: &addr) { Array($0) }
                // 排除 fe80::/10 链路本地地址，只认 ULA (fc00::/7, 如 FakeIP fdfe::) 或公网 IPv6
                if bytes.count == 16 && !(bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80) {
                    activeNames.insert(name)
                }
            }
        }
        return activeNames.sorted()
    }

    public static func readSystemHTTPProxy() -> String? {
        guard let dict = SCDynamicStoreCopyProxies(nil) as? [String: Any] else {
            return nil
        }
        if let httpEnable = dict[kCFNetworkProxiesHTTPEnable as String] as? Int,
           httpEnable == 1,
           let host = dict[kCFNetworkProxiesHTTPProxy as String] as? String,
           !host.isEmpty,
           let port = dict[kCFNetworkProxiesHTTPPort as String] as? Int,
           port > 0 {
            return "\(host):\(port)"
        }
        if let socksEnable = dict[kCFNetworkProxiesSOCKSEnable as String] as? Int,
           socksEnable == 1,
           let host = dict[kCFNetworkProxiesSOCKSProxy as String] as? String,
           !host.isEmpty,
           let port = dict[kCFNetworkProxiesSOCKSPort as String] as? Int,
           port > 0 {
            return "socks5://\(host):\(port)"
        }
        return nil
    }
}
