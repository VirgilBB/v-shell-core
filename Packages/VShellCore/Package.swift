// swift-tools-version:5.10
// Versions pinned exactly (transitive ones too, so resolution can't pull a
// release younger than 7 days; the 'not used by any target' warnings are expected); each was released at least 7 days before 2026-11-01.
import PackageDescription

let package = Package(
    name: "VShellCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "VShellCore", targets: ["VShellCore"]),
        .library(name: "VShellSSH", targets: ["VShellSSH"]),
    ],
    dependencies: [
        // Vendored swift-nio-ssh 0.15.0 + keyboard-interactive patch (see ../swift-nio-ssh/VSHELL-PATCHES.md)
        .package(path: "../swift-nio-ssh"),
        .package(url: "https://github.com/apple/swift-nio.git", exact: "2.104.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.2"),
        .package(url: "https://github.com/apple/swift-atomics.git", exact: "1.3.1"),
        .package(url: "https://github.com/apple/swift-collections.git", exact: "1.7.3"),
        .package(url: "https://github.com/apple/swift-system.git", exact: "1.8.1"),
        .package(url: "https://github.com/apple/swift-asn1.git", exact: "1.7.3"),
    ],
    targets: [
        .target(name: "VShellCore"),
        .target(name: "VShellSSH", dependencies: [
            "VShellCore",
            .product(name: "NIOSSH", package: "swift-nio-ssh"),
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "Crypto", package: "swift-crypto"),
        ]),
        .testTarget(name: "VShellCoreTests", dependencies: ["VShellCore"]),
        .testTarget(name: "VShellSSHTests", dependencies: ["VShellSSH", "VShellCore"]),
    ]
)
