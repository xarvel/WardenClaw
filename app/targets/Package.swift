// swift-tools-version:5.9
// SPDX-License-Identifier: Apache-2.0
// The Swift implementation of the WardenClaw protocol that the Apple Watch app compiles in
// (targets/watch/Protocol), as a package so its tests run without Xcode or a simulator:
//
//   cd app/targets && swift test          # macOS (CryptoKit) or Linux (built-in SHA-256)
//
// The tests read the shared vectors in protocol/vectors/ (the same files wardend, the app and the
// plugin are checked against). This package is not linked into the watch app: the app target
// compiles the same files directly (a folder of the @bacons/apple-targets target).
import PackageDescription

let package = Package(
  name: "WardenProtocol",
  platforms: [.macOS(.v13), .iOS(.v16), .watchOS(.v10)],
  products: [.library(name: "WardenProtocol", targets: ["WardenProtocol"])],
  targets: [
    .target(name: "WardenProtocol", path: "watch/Protocol"),
    .testTarget(name: "WardenProtocolTests", dependencies: ["WardenProtocol"], path: "WardenProtocolTests"),
  ]
)
