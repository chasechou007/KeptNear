// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "PSWMac",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "PSWMac", targets: ["PSWMac"])
    ],
    targets: [
        .executableTarget(name: "PSWMac"),
        .testTarget(
            name: "PSWMacTests",
            dependencies: ["PSWMac"]
        )
    ]
)
