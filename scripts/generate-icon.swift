#!/usr/bin/env swift
import AppKit
import CoreGraphics
import Foundation

// 生成符合 Apple HIG 层叠几何风格的原生盾牌图标 PNG（供 iconutil 打包 AppIcon.icns）
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

// 1. macOS 标准圆角矩形底座（留出规范外边距）
let pad = dim * 0.095
let cardRect = CGRect(x: pad, y: pad, width: dim - pad * 2, height: dim - pad * 2)
let corner = cardRect.width * 0.225
let bgPath = CGPath(roundedRect: cardRect, cornerWidth: corner, cornerHeight: corner, transform: nil)

ctx.saveGState()
ctx.addPath(bgPath)
ctx.clip()

let bgColors = [
    CGColor(srgbRed: 0.09, green: 0.14, blue: 0.28, alpha: 1.0),
    CGColor(srgbRed: 0.05, green: 0.08, blue: 0.16, alpha: 1.0)
] as CFArray
if let grad = CGGradient(colorsSpace: colorSpace, colors: bgColors, locations: [0.0, 1.0]) {
    ctx.drawLinearGradient(
        grad,
        start: CGPoint(x: dim * 0.5, y: dim - pad),
        end: CGPoint(x: dim * 0.5, y: pad),
        options: []
    )
}
ctx.restoreGState()

// 细微高光描边
ctx.saveGState()
ctx.addPath(bgPath)
ctx.setStrokeColor(CGColor(srgbRed: 1.0, green: 1.0, blue: 1.0, alpha: 0.16))
ctx.setLineWidth(max(1.0, dim * 0.012))
ctx.strokePath()
ctx.restoreGState()

// 2. 中心层叠盾牌主体
let cx = dim * 0.5
let topY = dim * 0.77
let midY = dim * 0.48
let botY = dim * 0.22
let halfW = dim * 0.255

let shield = CGMutablePath()
shield.move(to: CGPoint(x: cx, y: topY))
shield.addCurve(
    to: CGPoint(x: cx + halfW, y: topY - dim * 0.06),
    control1: CGPoint(x: cx + halfW * 0.45, y: topY),
    control2: CGPoint(x: cx + halfW * 0.85, y: topY - dim * 0.02)
)
shield.addCurve(
    to: CGPoint(x: cx, y: botY),
    control1: CGPoint(x: cx + halfW, y: midY - dim * 0.06),
    control2: CGPoint(x: cx + halfW * 0.55, y: botY + dim * 0.06)
)
shield.addCurve(
    to: CGPoint(x: cx - halfW, y: topY - dim * 0.06),
    control1: CGPoint(x: cx - halfW * 0.55, y: botY + dim * 0.06),
    control2: CGPoint(x: cx - halfW, y: midY - dim * 0.06)
)
shield.addCurve(
    to: CGPoint(x: cx, y: topY),
    control1: CGPoint(x: cx - halfW * 0.85, y: topY - dim * 0.02),
    control2: CGPoint(x: cx - halfW * 0.45, y: topY)
)
shield.closeSubpath()

ctx.saveGState()
ctx.setShadow(
    offset: CGSize(width: 0, height: -dim * 0.02),
    blur: dim * 0.045,
    color: CGColor(srgbRed: 0, green: 0, blue: 0, alpha: 0.42)
)
ctx.addPath(shield)
ctx.clip()

let shieldColors = [
    CGColor(srgbRed: 0.22, green: 0.78, blue: 0.58, alpha: 1.0),
    CGColor(srgbRed: 0.11, green: 0.52, blue: 0.86, alpha: 1.0)
] as CFArray
if let sGrad = CGGradient(colorsSpace: colorSpace, colors: shieldColors, locations: [0.0, 1.0]) {
    ctx.drawLinearGradient(
        sGrad,
        start: CGPoint(x: cx - halfW, y: topY),
        end: CGPoint(x: cx + halfW, y: botY),
        options: []
    )
}
ctx.restoreGState()

// 3. 盾牌内部校验对勾标记
let check = CGMutablePath()
check.move(to: CGPoint(x: cx - dim * 0.095, y: dim * 0.49))
check.addLine(to: CGPoint(x: cx - dim * 0.02, y: dim * 0.415))
check.addLine(to: CGPoint(x: cx + dim * 0.11, y: dim * 0.555))

ctx.saveGState()
ctx.addPath(check)
ctx.setStrokeColor(CGColor(srgbRed: 1.0, green: 1.0, blue: 1.0, alpha: 0.96))
ctx.setLineWidth(max(1.5, dim * 0.052))
ctx.setLineCap(.round)
ctx.setLineJoin(.round)
ctx.strokePath()
ctx.restoreGState()

guard let cgImage = ctx.makeImage() else { exit(1) }
let rep = NSBitmapImageRep(cgImage: cgImage)
guard let pngData = rep.representation(using: .png, properties: [:]) else { exit(1) }
try pngData.write(to: URL(fileURLWithPath: outPath))
