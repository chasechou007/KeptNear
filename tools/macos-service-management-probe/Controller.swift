import Foundation
import ServiceManagement

private let servicePlistPrefix = "com.chasechou.keptnear.service-probe."

private func servicePlistName() -> String {
    guard
        let name = ProcessInfo.processInfo.environment["KEPTNEAR_SERVICE_PROBE_PLIST_NAME"],
        name.hasPrefix(servicePlistPrefix),
        name.hasSuffix(".plist"),
        name.count <= 128,
        name.unicodeScalars.allSatisfy({
            CharacterSet.alphanumerics.union(CharacterSet(charactersIn: ".-")).contains($0)
        })
    else {
        FileHandle.standardError.write(Data("service probe plist name is invalid\n".utf8))
        exit(1)
    }
    return name
}

private func statusName(_ status: SMAppService.Status) -> String {
    switch status {
    case .notRegistered:
        "not-registered"
    case .enabled:
        "enabled"
    case .requiresApproval:
        "requires-approval"
    case .notFound:
        "not-found"
    @unknown default:
        "unknown"
    }
}

private func writeResult(
    command: String,
    service: SMAppService,
    ok: Bool,
    error: Error? = nil
) {
    var result: [String: Any] = [
        "command": command,
        "ok": ok,
        "status": statusName(service.status),
    ]
    if let error = error as NSError? {
        result["errorDomain"] = error.domain
        result["errorCode"] = error.code
    }

    guard
        let data = try? JSONSerialization.data(
            withJSONObject: result,
            options: [.sortedKeys]
        )
    else {
        FileHandle.standardError.write(Data("probe result encoding failed\n".utf8))
        exit(1)
    }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data("\n".utf8))
}

guard #available(macOS 13.0, *) else {
    FileHandle.standardError.write(Data("service probe requires macOS 13 or newer\n".utf8))
    exit(1)
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard arguments.count == 1 else {
    FileHandle.standardError.write(Data("usage: KeptNearServiceProbe status|register|unregister\n".utf8))
    exit(2)
}

let command = arguments[0]
let service = SMAppService.agent(plistName: servicePlistName())

switch command {
case "status":
    writeResult(command: command, service: service, ok: true)
case "register":
    do {
        try service.register()
        writeResult(command: command, service: service, ok: true)
    } catch {
        writeResult(command: command, service: service, ok: false, error: error)
        exit(1)
    }
case "unregister":
    do {
        try service.unregister()
        writeResult(command: command, service: service, ok: true)
    } catch {
        writeResult(command: command, service: service, ok: false, error: error)
        exit(1)
    }
default:
    FileHandle.standardError.write(Data("unknown service probe command\n".utf8))
    exit(2)
}
