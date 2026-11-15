#!/usr/bin/env swift
import AppKit
import CoreGraphics
import Foundation

// 生成 ClaudeGuard 应用图标 PNG（品牌标记「三线归一」，供 iconutil 打包 AppIcon.icns）
guard CommandLine.arguments.count >= 3,
      let size = Int(CommandLine.arguments[1]) else {
    fputs("Usage: generate-icon.swift <pixel_size> <output_png>\n", stderr)
    exit(1)
}
let outPath = CommandLine.arguments[2]
let dim = CGFloat(size)

let colorSpace = CGColorSpace(name: CGColorSpace.displayP3) ?? CGColorSpaceCreateDeviceRGB()
guard let ctx = CGContext(
    data: nil,
    width: size,
    height: size,
    bitsPerComponent: 8,
    bytesPerRow: 0,
    space: colorSpace,
    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
) else {
    exit(1)
}

ctx.setAllowsAntialiasing(true)
ctx.setShouldAntialias(true)

// 设计稿坐标系为 128×128（y 向下），这里换算到 CoreGraphics（y 向上）
let unit = dim / 128.0
func pt(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: x * unit, y: dim - y * unit) }

// 1. macOS 标准圆角矩形底座：石墨色渐变
let cardRect = CGRect(x: 12 * unit, y: 12 * unit, width: 104 * unit, height: 104 * unit)
let corner = 24 * unit
let bgPath = CGPath(roundedRect: cardRect, cornerWidth: corner, cornerHeight: corner, transform: nil)

ctx.saveGState()
ctx.addPath(bgPath)
ctx.clip()
let bgColors = [
    CGColor(srgbRed: 0x2B / 255.0, green: 0x30 / 255.0, blue: 0x40 / 255.0, alpha: 1.0),
    CGColor(srgbRed: 0x14 / 255.0, green: 0x16 / 255.0, blue: 0x1C / 255.0, alpha: 1.0)
] as CFArray
if let grad = CGGradient(colorsSpace: colorSpace, colors: bgColors, locations: [0.0, 1.0]) {
    ctx.drawLinearGradient(grad, start: pt(64, 12), end: pt(64, 116), options: [])
}
ctx.restoreGState()

// 细微高光描边
ctx.saveGState()
ctx.addPath(bgPath)
ctx.setStrokeColor(CGColor(srgbRed: 1.0, green: 1.0, blue: 1.0, alpha: 0.14))
ctx.setLineWidth(max(1.0, 1.5 * unit))
ctx.strokePath()
ctx.restoreGState()

// 2. 品牌标记「三线归一」：三条探测线收敛到同一个出口
let lanes = CGMutablePath()
lanes.move(to: pt(30, 40))
lanes.addLine(to: pt(56, 40))
lanes.addCurve(to: pt(84, 64), control1: pt(70, 40), control2: pt(70, 64))
lanes.move(to: pt(30, 64))
lanes.addLine(to: pt(84, 64))
lanes.move(to: pt(30, 88))
lanes.addLine(to: pt(56, 88))
lanes.addCurve(to: pt(84, 64), control1: pt(70, 88), control2: pt(70, 64))

ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -1.5 * unit), blur: 4 * unit, color: CGColor(srgbRed: 0, green: 0, blue: 0, alpha: 0.35))
ctx.addPath(lanes)
ctx.setStrokeColor(CGColor(srgbRed: 1.0, green: 1.0, blue: 1.0, alpha: 0.95))
ctx.setLineWidth(max(1.5, 6 * unit))
ctx.setLineCap(.round)
ctx.setLineJoin(.round)
ctx.strokePath()
ctx.restoreGState()

// 3. 出口：绿色节点 + 柔光
let exitCenter = pt(90, 64)
let glowColors = [
    CGColor(srgbRed: 0x32 / 255.0, green: 0xD7 / 255.0, blue: 0x4B / 255.0, alpha: 0.55),
    CGColor(srgbRed: 0x32 / 255.0, green: 0xD7 / 255.0, blue: 0x4B / 255.0, alpha: 0.0)
] as CFArray
if let glow = CGGradient(colorsSpace: colorSpace, colors: glowColors, locations: [0.0, 1.0]) {
    ctx.drawRadialGradient(glow, startCenter: exitCenter, startRadius: 0, endCenter: exitCenter, endRadius: 20 * unit, options: [])
}
let dotRect = CGRect(x: exitCenter.x - 9 * unit, y: exitCenter.y - 9 * unit, width: 18 * unit, height: 18 * unit)
ctx.setFillColor(CGColor(srgbRed: 0x32 / 255.0, green: 0xD7 / 255.0, blue: 0x4B / 255.0, alpha: 1.0))
ctx.fillEllipse(in: dotRect)
ctx.setStrokeColor(CGColor(srgbRed: 1.0, green: 1.0, blue: 1.0, alpha: 0.6))
ctx.setLineWidth(max(1.0, 2 * unit))
ctx.strokeEllipse(in: dotRect.insetBy(dx: unit, dy: unit))

guard let cgImage = ctx.makeImage() else { exit(1) }
let rep = NSBitmapImageRep(cgImage: cgImage)
guard let pngData = rep.representation(using: .png, properties: [:]) else { exit(1) }
try pngData.write(to: URL(fileURLWithPath: outPath))
