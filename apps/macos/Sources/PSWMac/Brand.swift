import AppKit
import SwiftUI

enum KeptNearBrand {
    static let name = "KeptNear"
    static let englishDescriptor = "Local-first password manager"
    static let simplifiedChineseDescriptor = "本地密码管理器"

    static let primary = adaptiveColor(
        name: "KeptNearPrimary",
        light: color(red: 0x24, green: 0x6B, blue: 0x5E),
        dark: color(red: 0x65, green: 0xC2, blue: 0xAE)
    )
    static let secondary = adaptiveColor(
        name: "KeptNearSecondary",
        light: color(red: 0xD9, green: 0x68, blue: 0x4A),
        dark: color(red: 0xE0, green: 0x7A, blue: 0x5F)
    )
    static let graphite = adaptiveColor(
        name: "KeptNearGraphite",
        light: color(red: 0x20, green: 0x27, blue: 0x24),
        dark: color(red: 0xF3, green: 0xF5, blue: 0xF1)
    )

    private static func color(red: Int, green: Int, blue: Int) -> NSColor {
        NSColor(
            srgbRed: CGFloat(red) / 255,
            green: CGFloat(green) / 255,
            blue: CGFloat(blue) / 255,
            alpha: 1
        )
    }

    private static func adaptiveColor(name: String, light: NSColor, dark: NSColor) -> Color {
        let color = NSColor(name: NSColor.Name(name)) { appearance in
            appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
        }
        return Color(nsColor: color)
    }
}

struct KeptNearMark: View {
    var body: some View {
        Canvas { context, size in
            let scale = min(size.width, size.height) / 512
            let offsetX = (size.width - (512 * scale)) / 2
            let offsetY = (size.height - (512 * scale)) / 2

            var markContext = context
            markContext.translateBy(x: offsetX, y: offsetY)
            markContext.scaleBy(x: scale, y: scale)
            markContext.fill(Self.leftBack, with: .color(KeptNearBrand.graphite))
            markContext.fill(Self.leftFront, with: .color(KeptNearBrand.primary))
            markContext.fill(Self.rightBack, with: .color(KeptNearBrand.graphite))
            markContext.fill(Self.rightFront, with: .color(KeptNearBrand.secondary))
        }
        .aspectRatio(1, contentMode: .fit)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(KeptNearBrand.name))
    }

    private static let leftBack = Path { path in
        path.move(to: CGPoint(x: 82, y: 172))
        path.addLine(to: CGPoint(x: 212, y: 104))
        path.addCurve(
            to: CGPoint(x: 244, y: 124),
            control1: CGPoint(x: 227, y: 96),
            control2: CGPoint(x: 244, y: 107)
        )
        path.addLine(to: CGPoint(x: 244, y: 246))
        path.addLine(to: CGPoint(x: 82, y: 178))
        path.addCurve(
            to: CGPoint(x: 82, y: 172),
            control1: CGPoint(x: 76, y: 176),
            control2: CGPoint(x: 76, y: 175)
        )
        path.closeSubpath()
    }

    private static let leftFront = Path { path in
        path.move(to: CGPoint(x: 82, y: 178))
        path.addLine(to: CGPoint(x: 244, y: 246))
        path.addLine(to: CGPoint(x: 244, y: 405))
        path.addCurve(
            to: CGPoint(x: 200, y: 431),
            control1: CGPoint(x: 244, y: 428),
            control2: CGPoint(x: 220, y: 442)
        )
        path.addLine(to: CGPoint(x: 98, y: 377))
        path.addCurve(
            to: CGPoint(x: 76, y: 339),
            control1: CGPoint(x: 84, y: 370),
            control2: CGPoint(x: 76, y: 355)
        )
        path.addLine(to: CGPoint(x: 76, y: 193))
        path.addCurve(
            to: CGPoint(x: 82, y: 178),
            control1: CGPoint(x: 76, y: 185),
            control2: CGPoint(x: 78, y: 180)
        )
        path.closeSubpath()
    }

    private static let rightBack = Path { path in
        path.move(to: CGPoint(x: 430, y: 172))
        path.addLine(to: CGPoint(x: 300, y: 104))
        path.addCurve(
            to: CGPoint(x: 268, y: 124),
            control1: CGPoint(x: 285, y: 96),
            control2: CGPoint(x: 268, y: 107)
        )
        path.addLine(to: CGPoint(x: 268, y: 246))
        path.addLine(to: CGPoint(x: 430, y: 178))
        path.addCurve(
            to: CGPoint(x: 430, y: 172),
            control1: CGPoint(x: 436, y: 176),
            control2: CGPoint(x: 436, y: 175)
        )
        path.closeSubpath()
    }

    private static let rightFront = Path { path in
        path.move(to: CGPoint(x: 430, y: 178))
        path.addLine(to: CGPoint(x: 268, y: 246))
        path.addLine(to: CGPoint(x: 268, y: 405))
        path.addCurve(
            to: CGPoint(x: 312, y: 431),
            control1: CGPoint(x: 268, y: 428),
            control2: CGPoint(x: 292, y: 442)
        )
        path.addLine(to: CGPoint(x: 414, y: 377))
        path.addCurve(
            to: CGPoint(x: 436, y: 339),
            control1: CGPoint(x: 428, y: 370),
            control2: CGPoint(x: 436, y: 355)
        )
        path.addLine(to: CGPoint(x: 436, y: 193))
        path.addCurve(
            to: CGPoint(x: 430, y: 178),
            control1: CGPoint(x: 436, y: 185),
            control2: CGPoint(x: 434, y: 180)
        )
        path.closeSubpath()
    }
}
