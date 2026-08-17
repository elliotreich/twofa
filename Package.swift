// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "TwoFA",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "twofa", targets: ["TwoFA"])
    ],
    targets: [
        .executableTarget(
            name: "TwoFA",
            path: ".",
            exclude: ["README.md", "LICENSE", ".gitignore"],
            sources: ["main.swift"]
        )
    ]
)
