// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SecurePailCrypto",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "SecurePailCrypto", targets: ["SecurePailCrypto"]),
    ],
    targets: [
        .target(name: "SecurePailCrypto"),
        .testTarget(
            name: "SecurePailCryptoTests",
            dependencies: ["SecurePailCrypto"],
            resources: [.copy("Resources/portable-vectors.json")]),
    ])
