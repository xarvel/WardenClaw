// SPDX-License-Identifier: GPL-3.0-or-later
// The watch talks to wardend itself, over HTTPS (URLSession; an independent watchOS app may not
// open sockets or WebSockets, TN3135). Same transport as the phone (protocol/README.md, section 5):
//
//   GET  /v1/ping?nonce          the server at this address holds the key from the pairing link
//   POST /v1/pair                pairing with a one-time code, alg "es256", signed by the new key
//   GET  /v1/pair/status?id      waiting for `wardend pair approve`
//   GET  /v1/pending?since&wait  long poll, at most 25 s
//   POST /v1/decide              an exec ticket for the pinned supervisorId, signed by the watch key
//   POST /v1/push/register       {deviceId, platform:"apns", token, topic, environment}
//   POST /v1/push/unregister     {deviceId, platform, token?}
//
// Every response must carry X-Wardend-Signature: Ed25519 by the supervisor key pinned from the
// pairing link over a string bound to this request: canonicalJson({type:"wardenclaw.resp.v1",
// action, deviceId, nonce, status, bodySha256[, id, digest]}) (the ticket id and digest for decide),
// or the ping type for /v1/ping. Anything else is dropped: a tunnel or a proxy can neither inject a
// card, nor pose as the server, nor pass the response to another request (a ping) off as the answer
// to decide. A signed rejection made before wardend checked the request (resp.unauth.v1) is thrown
// as WardendError.unbound: its reason is shown, but it is not an answer to this request.
import CryptoKit
import Foundation

struct WardendError: Error, LocalizedError {
  let status: Int
  let reason: String
  /// A rejection before wardend checked the request: signed, but not bound to this request.
  var unbound = false
  var errorDescription: String? { "wardend: \(status) \(reason)" }
}

/// What the watch keeps about its server (Keychain, this device only).
struct Pairing: Codable, Equatable {
  var url: String
  /// Supervisor public key from the link, base64url of 32 bytes (pinned).
  var key: String
  var supervisorId: String
  var host: String
  var name: String
  var pairId: String?
  /// pending | approved | rejected | revoked | unknown
  var status: String
  var pushToken: String?
  var pushEnvironment: String?

  private static let service = "dev.wardenclaw.watch"
  private static let account = "pairing.v1"

  static func load() -> Pairing? {
    guard let d = try? Keychain.read(service: service, account: account) else { return nil }
    return try? JSONDecoder().decode(Pairing.self, from: d)
  }

  func save() throws {
    try Keychain.write(service: Pairing.service, account: Pairing.account, data: JSONEncoder().encode(self))
  }

  static func delete() {
    Keychain.delete(service: service, account: account)
  }
}

final class WardendClient {
  let base: String
  let pinnedKey: String
  /// hex(sha256(pinnedKey)): the supervisorId pinned at pairing (Pairing.supervisorId is derived
  /// the same way). nil only for a malformed key, which also fails every response check.
  let supervisorId: String?
  let device: DeviceKey
  private let session: URLSession

  init(base: String, pinnedKey: String, device: DeviceKey) {
    self.base = base
    self.pinnedKey = pinnedKey
    supervisorId = WardenProtocol.supervisorId(keyB64url: pinnedKey)
    self.device = device
    let cfg = URLSessionConfiguration.default
    cfg.timeoutIntervalForRequest = 40
    cfg.waitsForConnectivity = false
    cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
    session = URLSession(configuration: cfg)
  }

  static func nonce() -> String { UUID().uuidString.lowercased() }
  static func nowMs() -> Int64 { Int64((Date().timeIntervalSince1970 * 1000).rounded()) }

  /// The single place where a request gets the device headers: GET requests sign
  /// {type:"wardenclaw.req.v1", supervisorId, action, deviceId, ts, nonce} with the pinned supervisorId,
  /// so a request is good only for this wardend; requests with a JSON body also sign the body.
  func signedHeaders(action: String, nonce: String, body: JSONValue? = nil) throws -> [String: String] {
    guard let sup = supervisorId else { throw WardendError(status: 0, reason: "bad_key") }
    let ts = WardendClient.nowMs()
    let s: String
    if let body = body {
      s = WardenProtocol.requestBodySigningString(supervisorId: sup, action: action, deviceId: device.deviceId, ts: ts, nonce: nonce, body: body)
    } else {
      s = WardenProtocol.requestSigningString(supervisorId: sup, action: action, deviceId: device.deviceId, ts: ts, nonce: nonce)
    }
    return [
      "X-Wardenclaw-Device": device.deviceId,
      "X-Wardenclaw-Ts": String(ts),
      "X-Wardenclaw-Nonce": nonce,
      "X-Wardenclaw-Signature": try device.signature(s),
    ]
  }

  /// Which response a request accepts: the ping type for its nonce, or a response bound to it.
  enum Expect {
    case ping(String)
    case bound(WardenProtocol.ResponseContext)
  }

  private func expect(_ action: String, _ nonce: String) -> Expect {
    .bound(WardenProtocol.ResponseContext(action: action, deviceId: device.deviceId, nonce: nonce))
  }

  /// A request whose response must be signed by the pinned key and bound to it (`want`).
  /// `allowNotOk`: return {ok:false,…} bodies (decide) instead of throwing; an unbound rejection always throws.
  func call(_ path: String, method: String = "GET", want: Expect, headers: [String: String] = [:], body: [UInt8]? = nil,
            timeout: TimeInterval = 15, allowNotOk: Bool = false) async throws -> JSONValue {
    guard let url = URL(string: base + path) else { throw WardendError(status: 0, reason: "bad_url") }
    var req = URLRequest(url: url, timeoutInterval: timeout)
    req.httpMethod = method
    for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
    if let body = body {
      req.setValue("application/json", forHTTPHeaderField: "Content-Type")
      req.httpBody = Data(body)
    }
    let (data, resp) = try await session.data(for: req)
    guard let http = resp as? HTTPURLResponse else { throw WardendError(status: 0, reason: "no_http_response") }
    let bytes = [UInt8](data)
    let json = (try? JSONParser.parse(bytes)) ?? .null
    switch verify(want, status: http.statusCode, body: bytes, json: json, signature: http.value(forHTTPHeaderField: "X-Wardend-Signature")) {
    case .bound: break
    case .unbound: throw WardendError(status: http.statusCode, reason: json["reason"]?.stringValue ?? "HTTP \(http.statusCode)", unbound: true)
    case .invalid: throw WardendError(status: http.statusCode, reason: "unsigned_response")
    }
    if !allowNotOk, !(200..<300).contains(http.statusCode) || json["ok"]?.boolValue == false {
      throw WardendError(status: http.statusCode, reason: json["reason"]?.stringValue ?? "HTTP \(http.statusCode)")
    }
    return json
  }

  enum Check { case bound, unbound, invalid }

  /// bound: signed by the pinned key and bound to this request (a ping to its nonce); unbound: a signed
  /// rejection ({ok:false}) of the same action made before wardend checked the request; invalid: anything else.
  private func verify(_ want: Expect, status: Int, body: [UInt8], json: JSONValue, signature: String?) -> Check {
    guard let sigS = signature, let sig = Bytes.unb64url(sigS), sig.count == 64,
          let raw = Bytes.unb64url(pinnedKey), raw.count == 32,
          let pub = try? Curve25519.Signing.PublicKey(rawRepresentation: raw) else { return .invalid }
    switch want {
    case .ping(let nonce):
      return pub.isValidSignature(sig, for: Array(WardenProtocol.pingSigningString(nonce: nonce, status: status, body: body).utf8)) ? .bound : .invalid
    case .bound(let ctx):
      if pub.isValidSignature(sig, for: Array(WardenProtocol.responseSigningString(ctx, status: status, body: body).utf8)) { return .bound }
      guard json["ok"]?.boolValue == false else { return .invalid }
      return pub.isValidSignature(sig, for: Array(WardenProtocol.unauthSigningString(action: ctx.action, status: status, body: body).utf8)) ? .unbound : .invalid
    }
  }

  // MARK: endpoints

  /// The server at `base` answers with the key from the link.
  func ping() async throws -> JSONValue {
    let n = WardendClient.nonce()
    return try await call("/v1/ping?nonce=" + n, want: .ping(n))
  }

  /// POST /v1/pair with alg "es256": the new watch key signs the pairing string, `alg` included.
  func pair(code: String, supervisorId: String, name: String) async throws -> JSONValue {
    let ts = WardendClient.nowMs()
    let n = WardendClient.nonce()
    let s = WardenProtocol.pairSigningString(code: code, deviceId: device.deviceId, pubkey: device.publicKeyB64, name: name,
                                             supervisorId: supervisorId, ts: ts, nonce: n, alg: "es256")
    let body: JSONValue = .obj([
      ("code", .string(code)), ("deviceId", .string(device.deviceId)), ("pubkey", .string(device.publicKeyB64)), ("alg", .string("es256")),
      ("name", .string(name)), ("supervisorId", .string(supervisorId)), ("ts", .int(ts)), ("nonce", .string(n)),
      ("signature", .string(try device.signature(s))),
    ])
    return try await call("/v1/pair", method: "POST", want: expect("pair", n), body: Canonical.bytes(body))
  }

  func pairStatus(id: String) async throws -> JSONValue {
    let n = WardendClient.nonce()
    let q = id.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? id
    return try await call("/v1/pair/status?id=" + q, want: expect("pair.status", n), headers: try signedHeaders(action: "pair.status", nonce: n))
  }

  func pending(since: Int64, waitMs: Int) async throws -> JSONValue {
    let n = WardendClient.nonce()
    return try await call("/v1/pending?since=\(since)&wait=\(waitMs)", want: expect("pending", n), headers: try signedHeaders(action: "pending", nonce: n),
                          timeout: TimeInterval(waitMs) / 1000 + 10)
  }

  /// Sign and send an exec ticket (ticketExecType) bound to the pinned supervisorId, so it is good
  /// only for this wardend. The watch never signs `risk` (it has no judge) nor `hw`.
  /// Returns wardend's {ok, reason?} as is, only when it is signed as the response to this ticket (its
  /// id and digest) and its body names the same id and decision. An unsigned or unbound response, or
  /// the response to another request (a ping), throws: the card stays, nothing is taken as decided.
  func decide(id: String, digest: String, decision: String) async throws -> JSONValue {
    guard let sup = supervisorId else { throw WardendError(status: 0, reason: "bad_key") }
    let ts = WardendClient.nowMs()
    let n = WardendClient.nonce()
    let type = WardenProtocol.ticketExecType
    let s = WardenProtocol.decisionSigningString(type: type, deviceId: device.deviceId, id: id, digest: digest, decision: decision, ts: ts, nonce: n,
                                                 supervisorId: sup)
    let ticket: JSONValue = .obj([
      ("deviceId", .string(device.deviceId)),
      ("payload", .obj([
        ("type", .string(type)), ("supervisorId", .string(sup)), ("id", .string(id)), ("digest", .string(digest)), ("decision", .string(decision)),
        ("ts", .int(ts)), ("nonce", .string(n)),
      ])),
      ("signature", .string(try device.signature(s))),
    ])
    let ctx = WardenProtocol.ResponseContext(action: "decide", deviceId: device.deviceId, nonce: n, id: id, digest: digest)
    let r = try await call("/v1/decide", method: "POST", want: .bound(ctx), body: Canonical.bytes(ticket), allowNotOk: true)
    guard WardenProtocol.decideResponseMatches(r, id: id, decision: decision) else { throw WardendError(status: 200, reason: "response_mismatch") }
    return r
  }

  func pushRegister(token: String, topic: String, environment: String) async throws -> JSONValue {
    let n = WardendClient.nonce()
    let body = WatchPush.registerBody(deviceId: device.deviceId, token: token, topic: topic, environment: environment)
    return try await call("/v1/push/register", method: "POST", want: expect("push.register", n), headers: try signedHeaders(action: "push.register", nonce: n, body: body), body: Canonical.bytes(body))
  }

  func pushUnregister(token: String?) async throws -> JSONValue {
    let n = WardendClient.nonce()
    let body = WatchPush.unregisterBody(deviceId: device.deviceId, token: token)
    return try await call("/v1/push/unregister", method: "POST", want: expect("push.unregister", n), headers: try signedHeaders(action: "push.unregister", nonce: n, body: body), body: Canonical.bytes(body))
  }
}
