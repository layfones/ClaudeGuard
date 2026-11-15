import SwiftUI
import AppKit
import ClaudeGuardCore

// ClaudeGuard 设计基础：颜色只表示判定，其它控件保持系统默认的单色外观。
// 对应 Figma「ClaudeGuard · Liquid Glass Redesign」中的 CG Tokens。

extension NSColor {
    /// 同时提供浅色、深色与「增强对比度」变体的动态颜色。
    static func guardDynamic(light: UInt32, dark: UInt32, lightHighContrast: UInt32, darkHighContrast: UInt32) -> NSColor {
        NSColor(name: nil) { appearance in
            let match = appearance.bestMatch(from: [
                .aqua, .darkAqua,
                .accessibilityHighContrastAqua, .accessibilityHighContrastDarkAqua
            ])
            switch match {
            case .darkAqua: return NSColor(guardHex: dark)
            case .accessibilityHighContrastAqua: return NSColor(guardHex: lightHighContrast)
            case .accessibilityHighContrastDarkAqua: return NSColor(guardHex: darkHighContrast)
            default: return NSColor(guardHex: light)
            }
        }
    }

    convenience init(guardHex hex: UInt32) {
        self.init(
            srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
            green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255,
            alpha: 1
        )
    }
}

extension Color {
    /// 放行（图形对比度：浅色 3.2:1，深色 7.8:1）
    static let guardPass = Color(nsColor: .guardDynamic(light: 0x1E9E4A, dark: 0x32D74B, lightHighContrast: 0x147535, darkHighContrast: 0x5BE36E))
    /// 拦截（浅色 4.0:1，深色 4.9:1）
    static let guardBlock = Color(nsColor: .guardDynamic(light: 0xE5352B, dark: 0xFF5A4F, lightHighContrast: 0xB8231B, darkHighContrast: 0xFF8077))
    /// 未确认（浅色 3.6:1，深色 7.6:1）
    static let guardHold = Color(nsColor: .guardDynamic(light: 0xC46A00, dark: 0xFFA62B, lightHighContrast: 0x9A5200, darkHighContrast: 0xFFBD5C))
}

extension VerdictPresentation.Tone {
    var color: Color {
        switch self {
        case .pass: return .guardPass
        case .block: return .guardBlock
        case .hold: return .guardHold
        case .neutral: return .secondary
        }
    }
}

// MARK: - 按钮

extension View {
    /// 每个视图唯一的主操作：macOS 26 起使用 Liquid Glass 强调样式。
    @ViewBuilder
    func guardProminentButton() -> some View {
        if #available(macOS 26.0, *) {
            self.buttonStyle(.glassProminent)
        } else {
            self.buttonStyle(.borderedProminent)
        }
    }
}

/// 菜单栏面板底部的菜单式行（悬停时整行高亮，与系统菜单一致）。
struct MenuRowButton: View {
    let title: String
    var shortcut: String? = nil
    let action: () -> Void

    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack {
                Text(title)
                Spacer(minLength: 8)
                if let shortcut {
                    Text(shortcut)
                        .foregroundStyle(hovering ? AnyShapeStyle(.white.opacity(0.85)) : AnyShapeStyle(.secondary))
                }
            }
            .font(.body)
            .foregroundStyle(hovering ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
            .padding(.horizontal, 10)
            .frame(height: 24)
            .contentShape(Rectangle())
            .background(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(hovering ? Color.accentColor : .clear)
            )
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}

/// 单色开关胶囊（守护的应用）：开启时浅灰底 + 对勾，关闭时描边 + 加号。
struct GuardChip: View {
    let title: String
    let isOn: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 4) {
                Image(systemName: isOn ? "checkmark" : "plus")
                    .font(.system(size: 9, weight: .bold))
                Text(title)
                    .font(.body)
            }
            .foregroundStyle(isOn ? .primary : .secondary)
            .padding(.leading, 8)
            .padding(.trailing, 10)
            .frame(height: 24)
            .background(Capsule().fill(Color.primary.opacity(isOn ? 0.1 : 0)))
            .overlay(Capsule().strokeBorder(Color.primary.opacity(isOn ? 0 : 0.14), lineWidth: 1))
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .focusEffectDisabled()
        .accessibilityAddTraits(isOn ? .isSelected : [])
    }
}

/// 判定字形：带浅色底的圆形 + 状态符号。
struct VerdictGlyph: View {
    let tone: VerdictPresentation.Tone
    let symbol: String

    var body: some View {
        ZStack {
            Circle().fill(tone.color.opacity(tone == .neutral ? 0.12 : 0.15))
            Image(systemName: symbol)
                .font(.system(size: 16, weight: .bold))
                .foregroundStyle(tone.color)
        }
        .frame(width: 36, height: 36)
        .accessibilityHidden(true)
    }
}

/// 设置与引导中使用的分组容器（内容层，不使用玻璃）。
struct GuardGroup<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(Color(nsColor: .controlBackgroundColor))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(Color(nsColor: .separatorColor), lineWidth: 1)
            )
    }
}

// MARK: - 表单

extension Text {
    /// 分组表单的说明文字：macOS 默认把页脚靠右排，这里统一靠左，便于阅读。
    func formFootnote() -> some View {
        self.frame(maxWidth: .infinity, alignment: .leading)
    }
}
