import AppKit
import CoreImage.CIFilterBuiltins
import Foundation

struct RecoveryKitDocumentCopy {
    let title: String
    let authorityWarningTitle: String
    let authorityWarningMessage: String
    let recoveryCodeLabel: String
    let vaultIdLabel: String
    let recoveryKeyIdLabel: String
    let generatedLabel: String
    let offlineStorageMessage: String
}

@MainActor
protocol RecoveryKitHandling {
    func savePDF(
        kit: RecoveryKitPayload,
        copy: RecoveryKitDocumentCopy,
        destinationURL: URL
    ) throws
    func printKit(kit: RecoveryKitPayload, copy: RecoveryKitDocumentCopy) throws
}

enum RecoveryKitDocumentError: Error {
    case qrGenerationFailed
    case pdfGenerationFailed
    case printingCancelled
}

enum RecoveryKitQRCode {
    static func image(payload: String, scale: CGFloat = 10) -> NSImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(payload.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else {
            return nil
        }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let representation = NSCIImageRep(ciImage: scaled)
        let image = NSImage(size: representation.size)
        image.addRepresentation(representation)
        return image
    }
}

@MainActor
final class MacRecoveryKitHandler: RecoveryKitHandling {
    func savePDF(
        kit: RecoveryKitPayload,
        copy: RecoveryKitDocumentCopy,
        destinationURL: URL
    ) throws {
        let view = try RecoveryKitPrintView(kit: kit, copy: copy)
        let data = view.dataWithPDF(inside: view.bounds)
        guard !data.isEmpty else {
            throw RecoveryKitDocumentError.pdfGenerationFailed
        }
        try data.write(to: destinationURL, options: .atomic)
    }

    func printKit(kit: RecoveryKitPayload, copy: RecoveryKitDocumentCopy) throws {
        let view = try RecoveryKitPrintView(kit: kit, copy: copy)
        let printInfo = NSPrintInfo()
        printInfo.paperSize = view.bounds.size
        printInfo.orientation = .portrait
        printInfo.topMargin = 0
        printInfo.bottomMargin = 0
        printInfo.leftMargin = 0
        printInfo.rightMargin = 0

        let operation = NSPrintOperation(view: view, printInfo: printInfo)
        operation.showsPrintPanel = true
        operation.showsProgressPanel = true
        guard operation.run() else {
            throw RecoveryKitDocumentError.printingCancelled
        }
    }
}

private final class RecoveryKitPrintView: NSView {
    private static let pageSize = NSSize(width: 612, height: 792)

    private let kit: RecoveryKitPayload
    private let copy: RecoveryKitDocumentCopy
    private let qrImage: NSImage

    init(kit: RecoveryKitPayload, copy: RecoveryKitDocumentCopy) throws {
        self.kit = kit
        self.copy = copy
        guard let qrImage = RecoveryKitQRCode.image(payload: kit.qrPayload) else {
            throw RecoveryKitDocumentError.qrGenerationFailed
        }
        self.qrImage = qrImage
        super.init(frame: NSRect(origin: .zero, size: Self.pageSize))
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        nil
    }

    override var isFlipped: Bool {
        true
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        NSColor.white.setFill()
        bounds.fill()

        let contentWidth: CGFloat = 504
        drawText(
            KeptNearBrand.name,
            in: NSRect(x: 54, y: 46, width: contentWidth, height: 28),
            font: .systemFont(ofSize: 14, weight: .semibold),
            color: .secondaryLabelColor
        )
        drawText(
            copy.title,
            in: NSRect(x: 54, y: 78, width: contentWidth, height: 44),
            font: .systemFont(ofSize: 30, weight: .bold),
            color: .labelColor
        )

        drawText(
            copy.authorityWarningTitle,
            in: NSRect(x: 54, y: 144, width: contentWidth, height: 24),
            font: .systemFont(ofSize: 14, weight: .bold),
            color: .systemRed
        )
        drawText(
            copy.authorityWarningMessage,
            in: NSRect(x: 54, y: 170, width: contentWidth, height: 44),
            font: .systemFont(ofSize: 11, weight: .regular),
            color: .labelColor
        )

        let qrRect = NSRect(x: 54, y: 238, width: 190, height: 190)
        NSGraphicsContext.current?.imageInterpolation = .none
        qrImage.draw(in: qrRect)

        drawText(
            copy.recoveryCodeLabel,
            in: NSRect(x: 274, y: 242, width: 284, height: 22),
            font: .systemFont(ofSize: 12, weight: .semibold),
            color: .secondaryLabelColor
        )
        drawText(
            kit.groupedCode,
            in: NSRect(x: 274, y: 270, width: 284, height: 150),
            font: .monospacedSystemFont(ofSize: 16, weight: .semibold),
            color: .labelColor,
            lineSpacing: 7
        )

        drawMetadata(
            label: copy.vaultIdLabel,
            value: kit.vaultId,
            y: 468
        )
        drawMetadata(
            label: copy.recoveryKeyIdLabel,
            value: kit.recoveryKeyId,
            y: 520
        )
        drawMetadata(
            label: copy.generatedLabel,
            value: Self.generationDate(kit.generatedAtUnixSeconds),
            y: 572
        )

        drawText(
            copy.offlineStorageMessage,
            in: NSRect(x: 54, y: 656, width: contentWidth, height: 54),
            font: .systemFont(ofSize: 11, weight: .medium),
            color: .labelColor
        )
    }

    private func drawMetadata(label: String, value: String, y: CGFloat) {
        drawText(
            label,
            in: NSRect(x: 54, y: y, width: 504, height: 18),
            font: .systemFont(ofSize: 10, weight: .semibold),
            color: .secondaryLabelColor
        )
        drawText(
            value,
            in: NSRect(x: 54, y: y + 20, width: 504, height: 24),
            font: .monospacedSystemFont(ofSize: 10, weight: .regular),
            color: .labelColor
        )
    }

    private func drawText(
        _ value: String,
        in rect: NSRect,
        font: NSFont,
        color: NSColor,
        lineSpacing: CGFloat = 3
    ) {
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineBreakMode = .byWordWrapping
        paragraph.lineSpacing = lineSpacing
        NSAttributedString(
            string: value,
            attributes: [
                .font: font,
                .foregroundColor: color,
                .paragraphStyle: paragraph
            ]
        ).draw(with: rect, options: [.usesLineFragmentOrigin, .usesFontLeading])
    }

    private static func generationDate(_ unixSeconds: UInt64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(unixSeconds))
        return ISO8601DateFormatter().string(from: date)
    }
}
