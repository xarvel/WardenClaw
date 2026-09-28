// SPDX-License-Identifier: GPL-3.0-or-later
// The watch's own device key: P-256 in the Secure Enclave (CryptoKit), never leaves the watch.
//
//   deviceId  = hex(sha256(65-byte SEC1 uncompressed public key))   (wardend, alg "es256")
//   signature = ECDSA P-256 / SHA-256, raw r||s (64 bytes), base64url
//
// Storage: the Secure Enclave key's `dataRepresentation` (an opaque blob that only this watch's
// Secure Enclave can use) sits in the Keychain as a generic password with
// kSecAttrAccessibleWhenUnlockedThisDeviceOnly: not in backups, not migrated to a new watch, not
// readable while the watch is locked (off the wrist). The key itself is created with the access
// control flag .privateKeyUsage only. `.userPresence` (passcode on every signature) is available
// behind WC_WATCH_USER_PRESENCE and off by default on purpose: it cannot be limited to one kind of
// signature, and this key also signs every long poll and every deny. The watch locks when it
// leaves the wrist, which makes the key unusable. See app/docs/BUILD.md ("Apple Watch" / key storage).
//
// The watch simulator has no Secure Enclave: there, and only there, a software P-256 key in the
// Keychain stands in, so the UI can be tried in Xcode. Device builds never take that path.
import CryptoKit
import Foundation
import Security

enum DeviceKeyError: Error, LocalizedError {
  case noSecureEnclave
  case accessControl(String)
  case keychain(OSStatus)

  var errorDescription: String? {
    switch self {
    case .noSecureEnclave: return "This watch has no Secure Enclave"
    case let .accessControl(m): return "Key access control: \(m)"
    case let .keychain(s): return "Keychain error \(s)"
    }
  }
}

struct DeviceKey {
  private let sign: (Data) throws -> Data
  /// 65 bytes, 0x04 || X || Y.
  let publicKeyX963: [UInt8]

  var deviceId: String { Bytes.sha256Hex(publicKeyX963) }
  var publicKeyB64: String { Bytes.b64url(publicKeyX963) }

  /// Signs the UTF-8 bytes of a protocol signing string; base64url of raw r||s.
  func signature(_ signingString: String) throws -> String {
    Bytes.b64url([UInt8](try sign(Data(signingString.utf8))))
  }

  private static let service = "dev.wardenclaw.watch"
  private static let account = "device-key.v1"

  static func load() throws -> DeviceKey? {
    guard let blob = try Keychain.read(service: service, account: account) else { return nil }
    return try make(blob)
  }

  static func loadOrCreate() throws -> DeviceKey {
    if let k = try load() { return k }
    #if targetEnvironment(simulator)
    let sk = P256.Signing.PrivateKey()
    try Keychain.write(service: service, account: account, data: sk.rawRepresentation)
    #else
    guard SecureEnclave.isAvailable else { throw DeviceKeyError.noSecureEnclave }
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    #if WC_WATCH_USER_PRESENCE
    flags.insert(.userPresence)
    #endif
    var err: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &err) else {
      throw DeviceKeyError.accessControl(err.map { String(describing: $0.takeRetainedValue()) } ?? "?")
    }
    let sk = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl: ac)
    try Keychain.write(service: service, account: account, data: sk.dataRepresentation)
    #endif
    guard let k = try load() else { throw DeviceKeyError.keychain(errSecItemNotFound) }
    return k
  }

  /// Forget the key (unpair). A new pairing creates a new key and a new deviceId.
  static func delete() {
    Keychain.delete(service: service, account: account)
  }

  private static func make(_ blob: Data) throws -> DeviceKey {
    #if targetEnvironment(simulator)
    let sk = try P256.Signing.PrivateKey(rawRepresentation: blob)
    return DeviceKey(sign: { try sk.signature(for: $0).rawRepresentation }, publicKeyX963: [UInt8](sk.publicKey.x963Representation))
    #else
    let sk = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob)
    return DeviceKey(sign: { try sk.signature(for: $0).rawRepresentation }, publicKeyX963: [UInt8](sk.publicKey.x963Representation))
    #endif
  }
}

/// Generic-password items, this-device-only, readable only while the watch is unlocked.
enum Keychain {
  static func read(service: String, account: String) throws -> Data? {
    let q: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var out: CFTypeRef?
    let st = SecItemCopyMatching(q as CFDictionary, &out)
    if st == errSecItemNotFound { return nil }
    guard st == errSecSuccess else { throw DeviceKeyError.keychain(st) }
    return out as? Data
  }

  static func write(service: String, account: String, data: Data) throws {
    delete(service: service, account: account)
    let q: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: account,
      kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      kSecValueData as String: data,
    ]
    let st = SecItemAdd(q as CFDictionary, nil)
    guard st == errSecSuccess else { throw DeviceKeyError.keychain(st) }
  }

  static func delete(service: String, account: String) {
    let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    SecItemDelete(q as CFDictionary)
  }
}
