// SPDX-License-Identifier: GPL-3.0-or-later
// YubiKey on iOS: the same JS API as the Android module (android/…/YubikeyModule.kt), on top of
// Yubico YubiKit for iOS (yubikit-ios 4.7.0, pinned in the Podfile by plugin/withYubikey.js).
// Raw CTAP2 (FIDO2) without a browser: clientDataHash comes from JS (the app binds it to the
// wardend ticket, see protocol/HARDWARE.md), the key signs authenticatorData || clientDataHash.
//
//   register(rpId, userId, userName, clientDataHash, pin?)  → {credentialId, attestationObject, alg}
//   getAssertion(rpId, clientDataHash, credentialId, pin?)  → {credentialId, authenticatorData, signature, signCount}
//   cancel()
//
// Transports on iPhone:
//   - NFC (iPhone 7 and newer): the system NFC sheet, the key is held to the top of the phone;
//   - Lightning (YubiKey 5Ci) only when the app declares com.yubico.ylp in
//     UISupportedExternalAccessoryProtocols (withYubikey option "lightning": true; App Store
//     builds then need Yubico's MFi registration, so it is off by default);
//   - USB-C (iPhone 15 and newer) is NOT available: YubiKit's USB-C path (YKFSmartCardConnection,
//     CryptoTokenKit) carries only smart-card applications, not FIDO2. hasUsb() is false.
// All bytes on the bridge are base64url without padding. Errors reject with the same codes as on
// Android (TIMEOUT, CANCELLED, PIN_REQUIRED, …), so the JS side and the translations are shared.

import ExpoModulesCore
import YubiKit

private let touchTimeout: TimeInterval = 45 // the wardend ticket window is 60 s
private let algEdDSA = -8
private let algES256 = -7

public class YubikeyModule: Module {
  private lazy var driver = YubikeyDriver(emit: { [weak self] transport, state in
    self?.sendEvent("onStatus", ["transport": transport, "state": state])
  })

  public func definition() -> ModuleDefinition {
    Name("Yubikey")

    Events("onStatus")

    Function("isSupported") { () -> Bool in
      YubikeyDriver.nfcSupported || YubikeyDriver.lightningDeclared
    }

    Function("hasNfc") { () -> Bool in
      YubikeyDriver.nfcSupported
    }

    // iOS has no NFC switch: if the hardware can read ISO 7816 tags, NFC is "on".
    Function("isNfcEnabled") { () -> Bool in
      YubikeyDriver.nfcSupported
    }

    // USB-C: YubiKit cannot run FIDO2 over it (see the header). Lightning counts as "usb" for the
    // JS side ("plug the key in"), but only when the app declares the accessory protocol.
    Function("hasUsb") { () -> Bool in
      YubikeyDriver.lightningDeclared
    }

    AsyncFunction("register") { (rpId: String, userId: String, userName: String, clientDataHash: String, pin: String?, promise: Promise) in
      guard let cdh = Data(b64url: clientDataHash), let uid = Data(b64url: userId) else {
        promise.reject("FAILED", "bad base64url argument")
        return
      }
      self.driver.run(promise: promise, pin: pin, prompt: "Hold your YubiKey to the top edge of the iPhone") { session, done in
        let rp = YKFFIDO2PublicKeyCredentialRpEntity()
        rp.rpId = rpId
        rp.rpName = "WardenClaw"
        let user = YKFFIDO2PublicKeyCredentialUserEntity()
        user.userId = uid
        user.userName = userName
        user.userDisplayName = userName
        let params: [YKFFIDO2PublicKeyCredentialParam] = [algEdDSA, algES256].map { alg in
          let p = YKFFIDO2PublicKeyCredentialParam()
          p.alg = alg
          return p
        }
        session.makeCredential(withClientDataHash: cdh, rp: rp, user: user, pubKeyCredParams: params, excludeList: nil, options: [YKFFIDO2OptionRK: false]) { response, error in
          guard let r = response else {
            done(.failure(YubikeyDriver.map(error)))
            return
          }
          // attestationObject = CBOR {fmt, authData, attStmt} over the RAW authData bytes, as on
          // Android: the packed attestation signature covers those exact bytes.
          guard let ad = r.authenticatorData, let credId = ad.credentialId, let cose = ad.coseEncodedCredentialPublicKey else {
            done(.failure(YubikeyError(code: "BAD_RESPONSE", message: "no attested credential data in the key response")))
            return
          }
          done(.success([
            "credentialId": credId.b64url,
            "attestationObject": r.webauthnAttestationObject.b64url,
            "alg": MiniCBOR.coseAlg(cose) ?? 0,
          ]))
        }
      }
    }

    AsyncFunction("getAssertion") { (rpId: String, clientDataHash: String, credentialId: String, pin: String?, promise: Promise) in
      guard let cdh = Data(b64url: clientDataHash), let credId = Data(b64url: credentialId) else {
        promise.reject("FAILED", "bad base64url argument")
        return
      }
      self.driver.run(promise: promise, pin: pin, prompt: "Hold your YubiKey to the top edge of the iPhone to sign") { session, done in
        let desc = YKFFIDO2PublicKeyCredentialDescriptor()
        desc.credentialId = credId
        let type = YKFFIDO2PublicKeyCredentialType()
        type.name = "public-key"
        desc.credentialType = type
        // Swift keeps the whole first selector piece here (unlike makeCredential(withClientDataHash:)),
        // as in Yubico's FIDO2Tests.swift for 4.7.0
        session.getAssertionWithClientDataHash(cdh, rpId: rpId, allowList: [desc], options: [YKFFIDO2OptionUP: true]) { response, error in
          guard let a = response else {
            done(.failure(YubikeyDriver.map(error)))
            return
          }
          // with a one-element allowList the key may leave the credential out of the response
          let id = a.credential?.credentialId ?? credId
          let ad = a.authData
          var count: UInt32 = 0
          if ad.count >= 37 {
            let b = [UInt8](ad)
            count = UInt32(b[33]) << 24 | UInt32(b[34]) << 16 | UInt32(b[35]) << 8 | UInt32(b[36])
          }
          done(.success(["credentialId": id.b64url, "authenticatorData": ad.b64url, "signature": a.signature.b64url, "signCount": Int(count)]))
        }
      }
    }

    AsyncFunction("cancel") {
      self.driver.finish(.failure(YubikeyError(code: "CANCELLED", message: "cancelled")))
    }

    OnAppEntersBackground {
      self.driver.finish(.failure(YubikeyError(code: "CANCELLED", message: "the app went to the background")))
    }

    OnDestroy {
      self.driver.finish(.failure(YubikeyError(code: "CANCELLED", message: "the module was unloaded")))
    }
  }
}

struct YubikeyError: Error {
  let code: String
  let message: String
}

typealias YubikeyResult = Result<[String: Any], YubikeyError>
typealias YubikeyOp = (YKFFIDO2Session, @escaping (YubikeyResult) -> Void) -> Void

/// One pending operation at a time; YubiKit callbacks arrive on its own queues, state is guarded by `lock`.
final class YubikeyDriver: NSObject, YKFManagerDelegate, YKFFIDO2SessionKeyStateDelegate {
  private let emit: (String, String) -> Void
  private let lock = NSLock()
  private var promise: Promise?
  private var op: YubikeyOp?
  private var pin: String?
  private var busy = false
  private var nfcOn = false
  private var accessoryOn = false
  private var timer: DispatchWorkItem?
  private var session: YKFFIDO2Session? // keeps the delegate target alive while a key is connected

  init(emit: @escaping (String, String) -> Void) {
    self.emit = emit
  }

  static var nfcSupported: Bool { YubiKitDeviceCapabilities.supportsISO7816NFCTags }

  /// Lightning (5Ci) only if the app declares Yubico's accessory protocol (see the header).
  static var lightningDeclared: Bool {
    let list = Bundle.main.object(forInfoDictionaryKey: "UISupportedExternalAccessoryProtocols") as? [String] ?? []
    return list.contains("com.yubico.ylp") && YubiKitDeviceCapabilities.supportsMFIAccessoryKey
  }

  func run(promise p: Promise, pin: String?, prompt: String, op: @escaping YubikeyOp) {
    let nfc = YubikeyDriver.nfcSupported
    let lightning = YubikeyDriver.lightningDeclared
    guard nfc || lightning else {
      p.reject("NFC_UNAVAILABLE", "this iPhone cannot read NFC security keys")
      return
    }
    lock.lock()
    if promise != nil {
      lock.unlock()
      p.reject("BUSY", "already waiting for a key tap")
      return
    }
    promise = p
    self.op = op
    self.pin = (pin?.isEmpty ?? true) ? nil : pin
    busy = false
    lock.unlock()

    DispatchQueue.main.async {
      let m = YubiKitManager.shared
      m.delegate = self
      if nfc {
        YubiKitExternalLocalization.nfcScanAlertMessage = prompt
        YubiKitExternalLocalization.nfcScanSuccessAlertMessage = "Done"
        m.startNFCConnection()
        self.nfcOn = true
      }
      if lightning {
        m.startAccessoryConnection()
        self.accessoryOn = true
      }
    }
    let t = DispatchWorkItem { [weak self] in
      self?.finish(.failure(YubikeyError(code: "TIMEOUT", message: "the key was not tapped within \(Int(touchTimeout)) s")))
    }
    timer = t
    DispatchQueue.main.asyncAfter(deadline: .now() + touchTimeout, execute: t)
  }

  // MARK: YKFManagerDelegate

  func didConnectNFC(_ connection: YKFNFCConnection) {
    runOn(connection, transport: "nfc")
  }

  func didDisconnectNFC(_ connection: YKFNFCConnection, error: Error?) {
    // The NFC sheet closed. If an operation is still pending, the user dismissed it or it timed out.
    guard isPending, let error = error else { return }
    finish(.failure(YubikeyDriver.mapNfc(error)))
  }

  func didFailConnectingNFC(_ error: Error) {
    guard isPending else { return }
    finish(.failure(YubikeyDriver.mapNfc(error)))
  }

  func didConnectAccessory(_ connection: YKFAccessoryConnection) {
    emit("usb", "connected")
    runOn(connection, transport: "usb")
  }

  func didDisconnectAccessory(_ connection: YKFAccessoryConnection, error: Error?) {
    emit("usb", "removed")
    lock.lock()
    busy = false
    lock.unlock()
  }

  // MARK: YKFFIDO2SessionKeyStateDelegate (Lightning: the key blinks and waits for a touch)

  func keyStateChanged(_ keyState: YKFFIDO2SessionKeyState) {
    if keyState == .touchKey { emit("usb", "touch") }
  }

  // MARK: exchange

  private var isPending: Bool {
    lock.lock()
    defer { lock.unlock() }
    return promise != nil
  }

  private func runOn(_ connection: YKFConnectionProtocol, transport: String) {
    lock.lock()
    guard promise != nil, !busy, let op = op else {
      lock.unlock()
      return
    }
    busy = true
    let pin = self.pin
    lock.unlock()

    connection.fido2Session { [weak self] session, error in
      guard let self = self else { return }
      guard let session = session else {
        self.lostOrFail(transport, YubikeyError(code: "FAILED", message: error?.localizedDescription ?? "could not open the FIDO2 session"))
        return
      }
      self.session = session
      if transport == "usb" { session.delegate = self }
      let exchange = {
        op(session) { result in
          self.finish(result)
        }
      }
      guard let pin = pin else {
        exchange()
        return
      }
      session.verifyPin(pin) { error in
        if let error = error {
          self.finish(.failure(YubikeyDriver.map(error)))
        } else {
          exchange()
        }
      }
    }
  }

  /// NFC: the key was moved away too early. The NFC sheet cannot wait for a second tap reliably,
  /// so report it; the UI offers "Try again". Lightning: wait for the key to be plugged in again.
  private func lostOrFail(_ transport: String, _ e: YubikeyError) {
    if transport == "usb" {
      lock.lock()
      busy = false
      lock.unlock()
      return
    }
    finish(.failure(e))
  }

  func finish(_ result: YubikeyResult) {
    lock.lock()
    guard let p = promise else {
      lock.unlock()
      return
    }
    promise = nil
    op = nil
    pin = nil
    busy = false
    let t = timer
    timer = nil
    lock.unlock()
    t?.cancel()

    DispatchQueue.main.async {
      let m = YubiKitManager.shared
      if self.nfcOn {
        switch result {
        case .success: m.stopNFCConnection(withMessage: "Done")
        case let .failure(e): m.stopNFCConnection(withErrorMessage: e.code == "CANCELLED" ? "Cancelled" : e.message)
        }
        self.nfcOn = false
      }
      if self.accessoryOn {
        m.stopAccessoryConnection()
        self.accessoryOn = false
      }
      // (the session's delegate is a nonnull assign property; the driver outlives it, so it stays set)
      self.session = nil
    }
    switch result {
    case let .success(v): p.resolve(v)
    case let .failure(e): p.reject(e.code, e.message)
    }
  }

  // MARK: errors

  /// CTAP status (YKFFIDO2Error.code) → the codes of the JS API.
  static func map(_ error: Error?) -> YubikeyError {
    guard let error = error else { return YubikeyError(code: "FAILED", message: "no response from the key") }
    let ns = error as NSError
    guard ns.isKind(of: YKFFIDO2Error.self) else {
      return YubikeyError(code: "FAILED", message: ns.localizedDescription)
    }
    // CTAP2 status codes (YKFFIDO2ErrorCode in YKFFIDO2Error.h; numeric to avoid guessing the
    // Swift spelling of the imported ALL_CAPS enum cases)
    let code: String
    switch ns.code {
    case 0x36: code = "PIN_REQUIRED" // PIN_REQUIRED
    case 0x31: code = "PIN_INVALID" // PIN_INVALID
    case 0x32, 0x34: code = "PIN_BLOCKED" // PIN_BLOCKED, PIN_AUTH_BLOCKED
    case 0x2E: code = "NO_CREDENTIALS" // NO_CREDENTIALS
    case 0x27, 0x30: code = "DENIED" // OPERATION_DENIED, NOT_ALLOWED
    case 0x26: code = "UNSUPPORTED_ALGORITHM" // UNSUPPORTED_ALGORITHM
    case 0x3A, 0x2F: code = "TIMEOUT" // ACTION_TIMEOUT, USER_ACTION_TIMEOUT
    case 0x2D: code = "CANCELLED" // KEEPALIVE_CANCEL
    default: code = "CTAP_ERROR"
    }
    return YubikeyError(code: code, message: "CTAP 0x" + String(ns.code, radix: 16) + ": " + ns.localizedDescription)
  }

  /// Core NFC session errors (NFCReaderError): 200 the user closed the sheet, 201 the sheet timed out.
  static func mapNfc(_ error: Error) -> YubikeyError {
    let ns = error as NSError
    if ns.domain == "NFCError" {
      switch ns.code {
      case 200: return YubikeyError(code: "CANCELLED", message: "cancelled")
      case 201: return YubikeyError(code: "TIMEOUT", message: "the NFC session timed out")
      case 1, 2: return YubikeyError(code: "NFC_UNAVAILABLE", message: ns.localizedDescription)
      default: break
      }
    }
    return YubikeyError(code: "FAILED", message: ns.localizedDescription)
  }
}

/// Just enough CBOR to read `alg` (key 3) from a COSE_Key map.
enum MiniCBOR {
  static func coseAlg(_ data: Data) -> Int? {
    var r = Reader(bytes: [UInt8](data))
    guard let h = r.head(), h.0 == 5 else { return nil }
    for _ in 0..<h.1 {
      guard let key = r.int() else { return nil }
      if key == 3 { return r.int() }
      guard r.skip() else { return nil }
    }
    return nil
  }

  struct Reader {
    let bytes: [UInt8]
    var i = 0

    mutating func head() -> (UInt8, Int)? {
      guard i < bytes.count else { return nil }
      let b = bytes[i]
      i += 1
      let major = b >> 5
      let info = b & 0x1F
      var n = 0
      switch info {
      case 0..<24: n = Int(info)
      case 24, 25, 26, 27:
        let len = 1 << Int(info - 24)
        guard i + len <= bytes.count else { return nil }
        for _ in 0..<len {
          n = n << 8 | Int(bytes[i])
          i += 1
        }
      default: return nil // indefinite lengths do not occur in COSE keys from a YubiKey
      }
      return (major, n)
    }

    mutating func int() -> Int? {
      guard let h = head() else { return nil }
      let (major, n) = h
      if major == 0 { return n }
      if major == 1 { return -1 - n }
      return nil
    }

    mutating func skip() -> Bool {
      guard let h = head() else { return false }
      let (major, n) = h
      switch major {
      case 0, 1, 7: return true
      case 2, 3:
        guard i + n <= bytes.count else { return false }
        i += n
        return true
      case 4:
        for _ in 0..<n where !skip() { return false }
        return true
      case 5:
        for _ in 0..<(2 * n) where !skip() { return false }
        return true
      case 6: return skip()
      default: return false
      }
    }
  }
}

extension Data {
  init?(b64url s: String) {
    var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while t.count % 4 != 0 { t += "=" }
    self.init(base64Encoded: t)
  }

  var b64url: String {
    base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }
}
