import Darwin
import Foundation

private func requiredEnvironment(_ name: String) -> String {
    guard let value = ProcessInfo.processInfo.environment[name], !value.isEmpty else {
        FileHandle.standardError.write(Data("service probe environment is incomplete\n".utf8))
        exit(1)
    }
    return value
}

let markerPath = requiredEnvironment("KEPTNEAR_SERVICE_PROBE_MARKER")
let generation = requiredEnvironment("KEPTNEAR_SERVICE_PROBE_GENERATION")

var executablePathSize: UInt32 = 0
_NSGetExecutablePath(nil, &executablePathSize)
var executablePathBuffer = [CChar](repeating: 0, count: Int(executablePathSize))
guard _NSGetExecutablePath(&executablePathBuffer, &executablePathSize) == 0 else {
    FileHandle.standardError.write(Data("service probe executable path failed\n".utf8))
    exit(1)
}

let result: [String: Any] = [
    "executable": URL(fileURLWithPath: String(cString: executablePathBuffer)).standardizedFileURL.path,
    "generation": generation,
    "pid": ProcessInfo.processInfo.processIdentifier,
]

do {
    let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
    try data.write(to: URL(fileURLWithPath: markerPath), options: [.atomic])
} catch {
    FileHandle.standardError.write(Data("service probe marker write failed\n".utf8))
    exit(1)
}

dispatchMain()
