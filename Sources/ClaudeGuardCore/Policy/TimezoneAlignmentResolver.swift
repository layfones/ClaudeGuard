import Foundation

/// 客户端进程级时区对齐模式（仅作用于受保护 AI 客户端进程及其子进程，绝不修改 macOS 系统时区）。
public enum TimezoneAlignmentMode: String, Codable, Sendable, CaseIterable, Identifiable {
    /// 根据探测到的出口国家码 `loc` 与机房 `colo` 自动推导匹配的 IANA 时区（默认推荐）
    case autoFromExit = "auto_from_exit"
    /// 始终注入用户手动指定的固定 IANA 时区
    case manual = "manual"
    /// 关闭时区注入，沿用本机系统时区
    case disabled = "disabled"

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .autoFromExit:
            return "自动跟随代理出口地区对齐（推荐）"
        case .manual:
            return "手动固定指定时区"
        case .disabled:
            return "关闭（沿用本机系统时区）"
        }
    }
}

/// 根据出口 IP 国家码与 Cloudflare 边缘机房代码推导自洽的 IANA 时区。
public enum TimezoneAlignmentResolver {
    public static let commonTimeZones: [(id: String, label: String)] = [
        ("America/Los_Angeles", "🇺🇸 美西 · 洛杉矶 (America/Los_Angeles)"),
        ("America/Denver", "🇺🇸 美山区 · 丹佛 (America/Denver)"),
        ("America/Chicago", "🇺🇸 美中 · 芝加哥/达拉斯 (America/Chicago)"),
        ("America/New_York", "🇺🇸 美东 · 纽约/弗吉尼亚 (America/New_York)"),
        ("Asia/Seoul", "🇰🇷 韩国 · 首尔 (Asia/Seoul)"),
        ("Asia/Tokyo", "🇯🇵 日本 · 东京 (Asia/Tokyo)"),
        ("Asia/Singapore", "🇸🇬 新加坡 (Asia/Singapore)"),
        ("Asia/Taipei", "🇹🇼 台湾 · 台北 (Asia/Taipei)"),
        ("Asia/Hong_Kong", "🇭🇰 香港 (Asia/Hong_Kong)"),
        ("Europe/London", "🇬🇧 英国 · 伦敦 (Europe/London)"),
        ("Europe/Berlin", "🇩🇪 德国 · 柏林/法兰克福 (Europe/Berlin)"),
        ("Europe/Amsterdam", "🇳🇱 荷兰 · 阿姆斯特丹 (Europe/Amsterdam)"),
        ("Europe/Paris", "🇫🇷 法国 · 巴黎 (Europe/Paris)"),
        ("America/Toronto", "🇨🇦 加拿大 · 多伦多 (America/Toronto)"),
        ("America/Vancouver", "🇨🇦 加拿大 · 温哥华 (America/Vancouver)"),
        ("Australia/Sydney", "🇦🇺 澳大利亚 · 悉尼 (Australia/Sydney)")
    ]

    /// 结合配置模式、出口国家码与边缘机房代码计算应注入的 IANA 时区标识符。
    public static func resolve(
        mode: TimezoneAlignmentMode,
        manualTimeZone: String,
        countryCode: String?,
        colo: String?
    ) -> String? {
        switch mode {
        case .disabled:
            return nil

        case .manual:
            let trimmed = manualTimeZone.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, isValidTimeZoneIdentifier(trimmed) else { return nil }
            return trimmed

        case .autoFromExit:
            let cc = countryCode?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
            let edge = colo?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()

            if let cc, !cc.isEmpty {
                // 多时区大国结合机房三字码精细匹配，避免跨海岸时差；单时区国家严格以国家码为准（防止邻国 CDN 节点误导）
                switch cc {
                case "US":
                    if let edge, let usTZ = usColoTimeZones[edge] {
                        return usTZ
                    }
                    return "America/Los_Angeles"
                case "CA":
                    if let edge, let caTZ = caColoTimeZones[edge] {
                        return caTZ
                    }
                    return "America/Toronto"
                case "AU":
                    if let edge, let auTZ = auColoTimeZones[edge] {
                        return auTZ
                    }
                    return "Australia/Sydney"
                default:
                    if let mapped = countryPrimaryTimeZones[cc], isValidTimeZoneIdentifier(mapped) {
                        return mapped
                    }
                }
            }

            if let edge, let fallback = fallbackColoTimeZones[edge], isValidTimeZoneIdentifier(fallback) {
                return fallback
            }
            return nil
        }
    }

    public static func isValidTimeZoneIdentifier(_ identifier: String) -> Bool {
        TimeZone(identifier: identifier) != nil
    }

    /// 读取 macOS 真实的系统全局时区（直接解析 `/etc/localtime` 软链目标，不受任何进程 `TZ` 变量影响）。
    public static func realMachineSystemTimeZoneIdentifier() -> String {
        if let dest = try? FileManager.default.destinationOfSymbolicLink(atPath: "/etc/localtime"),
           let range = dest.range(of: "zoneinfo/") {
            let id = String(dest[range.upperBound...])
            if !id.isEmpty, isValidTimeZoneIdentifier(id) {
                return id
            }
        }
        return TimeZone.current.identifier
    }

    /// 格式化展示形如 `Asia/Seoul (UTC+09:00)`。
    public static func formatDisplaySummary(for identifier: String, now: Date = Date()) -> String {
        guard let tz = TimeZone(identifier: identifier) else { return identifier }
        let seconds = tz.secondsFromGMT(for: now)
        let sign = seconds >= 0 ? "+" : "-"
        let absSec = abs(seconds)
        let hours = absSec / 3600
        let mins = (absSec % 3600) / 60
        return String(format: "%@ (UTC%@%02d:%02d)", identifier, sign, hours, mins)
    }

    // MARK: - 映射字典

    private static let usColoTimeZones: [String: String] = [
        // Pacific
        "LAX": "America/Los_Angeles", "SJC": "America/Los_Angeles", "SFO": "America/Los_Angeles",
        "SEA": "America/Los_Angeles", "PDX": "America/Los_Angeles", "SAN": "America/Los_Angeles",
        "LAS": "America/Los_Angeles", "SMF": "America/Los_Angeles", "ONT": "America/Los_Angeles",
        // Arizona
        "PHX": "America/Phoenix",
        // Mountain
        "DEN": "America/Denver", "SLC": "America/Denver", "ABQ": "America/Denver", "BOI": "America/Denver",
        // Central
        "ORD": "America/Chicago", "DFW": "America/Chicago", "IAH": "America/Chicago", "AUS": "America/Chicago",
        "MSP": "America/Chicago", "MCI": "America/Chicago", "STL": "America/Chicago", "MEM": "America/Chicago",
        "OMA": "America/Chicago", "OKC": "America/Chicago", "BNA": "America/Chicago", "SAT": "America/Chicago",
        // Eastern
        "EWR": "America/New_York", "IAD": "America/New_York", "JFK": "America/New_York", "LGA": "America/New_York",
        "BOS": "America/New_York", "ATL": "America/New_York", "MIA": "America/New_York", "CLT": "America/New_York",
        "PHL": "America/New_York", "DTW": "America/New_York", "PIT": "America/New_York", "CMH": "America/New_York",
        "RDU": "America/New_York", "TPA": "America/New_York", "MCO": "America/New_York", "BUF": "America/New_York",
        "IND": "America/Indiana/Indianapolis",
        // Hawaii / Alaska
        "HNL": "Pacific/Honolulu", "ANC": "America/Anchorage"
    ]

    private static let caColoTimeZones: [String: String] = [
        "YVR": "America/Vancouver",
        "YYC": "America/Edmonton", "YEG": "America/Edmonton",
        "YWG": "America/Winnipeg",
        "YYZ": "America/Toronto", "YUL": "America/Toronto", "YOW": "America/Toronto",
        "YHZ": "America/Halifax"
    ]

    private static let auColoTimeZones: [String: String] = [
        "PER": "Australia/Perth",
        "ADL": "Australia/Adelaide",
        "BNE": "Australia/Brisbane",
        "SYD": "Australia/Sydney", "MEL": "Australia/Sydney", "CBR": "Australia/Sydney"
    ]

    private static let fallbackColoTimeZones: [String: String] = [
        "ICN": "Asia/Seoul",
        "NRT": "Asia/Tokyo", "KIX": "Asia/Tokyo", "FUK": "Asia/Tokyo",
        "SIN": "Asia/Singapore",
        "HKG": "Asia/Hong_Kong",
        "TPE": "Asia/Taipei",
        "LHR": "Europe/London", "MAN": "Europe/London",
        "FRA": "Europe/Berlin", "MUC": "Europe/Berlin", "BER": "Europe/Berlin",
        "AMS": "Europe/Amsterdam",
        "CDG": "Europe/Paris",
        "ZRH": "Europe/Zurich"
    ]

    private static let countryPrimaryTimeZones: [String: String] = [
        "KR": "Asia/Seoul",
        "JP": "Asia/Tokyo",
        "SG": "Asia/Singapore",
        "TW": "Asia/Taipei",
        "HK": "Asia/Hong_Kong",
        "MO": "Asia/Macau",
        "MY": "Asia/Kuala_Lumpur",
        "TH": "Asia/Bangkok",
        "VN": "Asia/Ho_Chi_Minh",
        "PH": "Asia/Manila",
        "ID": "Asia/Jakarta",
        "IN": "Asia/Kolkata",
        "AE": "Asia/Dubai",
        "IL": "Asia/Jerusalem",
        "TR": "Europe/Istanbul",
        "GB": "Europe/London",
        "IE": "Europe/Dublin",
        "DE": "Europe/Berlin",
        "FR": "Europe/Paris",
        "NL": "Europe/Amsterdam",
        "CH": "Europe/Zurich",
        "AT": "Europe/Vienna",
        "BE": "Europe/Brussels",
        "LU": "Europe/Luxembourg",
        "ES": "Europe/Madrid",
        "PT": "Europe/Lisbon",
        "IT": "Europe/Rome",
        "SE": "Europe/Stockholm",
        "NO": "Europe/Oslo",
        "DK": "Europe/Copenhagen",
        "FI": "Europe/Helsinki",
        "IS": "Atlantic/Reykjavik",
        "PL": "Europe/Warsaw",
        "CZ": "Europe/Prague",
        "RO": "Europe/Bucharest",
        "GR": "Europe/Athens",
        "NZ": "Pacific/Auckland",
        "BR": "America/Sao_Paulo",
        "AR": "America/Argentina/Buenos_Aires",
        "CL": "America/Santiago",
        "MX": "America/Mexico_City",
        "ZA": "Africa/Johannesburg"
    ]
}
