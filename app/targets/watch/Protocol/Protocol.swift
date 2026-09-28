// SPDX-License-Identifier: Apache-2.0
// WardenClaw protocol v1 (protocol/README.md): exec envelope check, signing strings, pairing link.
// Same rules as app/src/core/execEnvelope.ts, canonical.ts and wardendProto.ts; the tests in
// Tests/ check them against protocol/vectors/*.json.

public enum WardenProtocol {
  /// Type of the request signing string: with the supervisorId it binds a request to one wardend
  /// (the gateway plugin signs {action, deviceId, ts, nonce} without a type).
  public static let reqType = "wardenclaw.req.v1"
  public static let pairType = "wardenclaw.pair.v1"
  /// Response to an authenticated request, bound to it (action, deviceId, nonce[, id, digest]).
  public static let respType = "wardenclaw.resp.v1"
  /// Response to /v1/ping: never passes for the response to another request.
  public static let pingType = "wardenclaw.ping.v1"
  /// Rejection before the request was authenticated: no caller nonce or deviceId, bound to nothing.
  public static let unauthType = "wardenclaw.resp.unauth.v1"
  /// Domain of the second-factor challenge: sha256(canonicalJson({type:"wardenclaw.hw.v1", ticket,
  /// deviceId, id, digest, decision, ts, nonce[, supervisorId][, risk]})), where `ticket` is the
  /// ticket type. Not computed here: the watch sends no second factor.
  public static let hwType = "wardenclaw.hw.v1"
  /// Ticket type of a wardend exec record: the only type the watch signs; carries supervisorId.
  public static let ticketExecType = "wardenclaw.ticket.exec.v1"
  /// Ticket type of a gateway plugin tool call; has no supervisorId.
  public static let ticketToolType = "wardenclaw.ticket.tool.v1"

  // MARK: exec envelope

  /// The 14 fields of envelope v1, sorted.
  static let envelopeKeys = ["argv", "cwd", "env", "envHash", "exe", "gid", "nonce", "pidfdCookie", "ppidChain", "requester", "ts", "type", "uid", "v"]

  /// Longest `env` value in the envelope, in code points (Unicode scalars); wardend cuts the rest.
  public static let envValueMax = 1024

  public struct ExecLink: Equatable {
    public let pid: Int64
    public let exe: String
  }

  /// A variable of the envelope's `env` (in envp order, repeats kept): what wardend chose to show
  /// because it changes how the program behaves. `cut`: code points cut off a longer value (nil: whole).
  public struct EnvVar: Equatable {
    public let name: String
    public let value: String
    public let cut: Int64?

    public init(name: String, value: String, cut: Int64? = nil) {
      self.name = name
      self.value = value
      self.cut = cut
    }
  }

  public struct ExecEnvelope {
    public let argv: [String]
    public let cwd: String
    public let exe: String
    public let uid: Int64
    public let gid: Int64
    public let ppidChain: [ExecLink]
    public let env: [EnvVar]
    public let envHash: String
    public let host: String
    public let supervisorId: String
    public let pidfdCookie: String
    public let ts: Int64
    public let nonce: String
    /// The parsed value the digest is computed over.
    public let value: JSONValue
  }

  /// One `env` entry, strictly: exactly {name, value} or {name, value, cut}; name a non-empty string
  /// without "=", value a string of at most envValueMax code points, cut an integer > 0.
  static func parseEnvVar(_ e: JSONValue) -> EnvVar? {
    guard let m = e.objectMembers, m.count == 2 || m.count == 3,
          let name = e["name"]?.stringValue, let value = e["value"]?.stringValue else { return nil }
    var cut: Int64?
    if m.count == 3 {
      guard let c = e["cut"]?.safeInteger, c > 0 else { return nil }
      cut = c
    }
    guard !name.isEmpty, !name.unicodeScalars.contains("="), value.unicodeScalars.count <= envValueMax else { return nil }
    return EnvVar(name: name, value: value, cut: cut)
  }

  /// Strict parse of envelope v1: exactly the 14 fields with the right types; nil otherwise.
  public static func parseEnvelope(_ v: JSONValue) -> ExecEnvelope? {
    guard let m = v.objectMembers else { return nil }
    let keys = m.map { $0.0 }.sorted { utf16Less($0, $1) }
    guard keys.count == envelopeKeys.count, zip(keys, envelopeKeys).allSatisfy({ sameCodeUnits($0, $1) }) else { return nil }
    guard v["v"]?.safeInteger == 1, let type = v["type"]?.stringValue, sameCodeUnits(type, "exec") else { return nil }
    guard let argvA = v["argv"]?.arrayValue else { return nil }
    var argv: [String] = []
    for a in argvA {
      guard let s = a.stringValue else { return nil }
      argv.append(s)
    }
    guard let cwd = v["cwd"]?.stringValue, let exe = v["exe"]?.stringValue, let envHash = v["envHash"]?.stringValue,
          let cookie = v["pidfdCookie"]?.stringValue, let nonce = v["nonce"]?.stringValue else { return nil }
    guard let uid = v["uid"]?.safeInteger, let gid = v["gid"]?.safeInteger, let ts = v["ts"]?.safeInteger else { return nil }
    guard let chainA = v["ppidChain"]?.arrayValue else { return nil }
    var chain: [ExecLink] = []
    for l in chainA {
      guard let lm = l.objectMembers, lm.count == 2, let pid = l["pid"]?.safeInteger, let lexe = l["exe"]?.stringValue else { return nil }
      chain.append(ExecLink(pid: pid, exe: lexe))
    }
    // env: an array (possibly empty, never null or absent) of strict entries
    guard let envA = v["env"]?.arrayValue else { return nil }
    var env: [EnvVar] = []
    env.reserveCapacity(envA.count)
    for e in envA {
      guard let ev = parseEnvVar(e) else { return nil }
      env.append(ev)
    }
    guard let r = v["requester"], let rm = r.objectMembers, rm.count == 2,
          let host = r["host"]?.stringValue, let sid = r["supervisorId"]?.stringValue else { return nil }
    return ExecEnvelope(argv: argv, cwd: cwd, exe: exe, uid: uid, gid: gid, ppidChain: chain, env: env, envHash: envHash,
                        host: host, supervisorId: sid, pidfdCookie: cookie, ts: ts, nonce: nonce, value: v)
  }

  /// digest = hex(sha256(canonicalJson(envelope))), over the envelope as received (the parsed JSON,
  /// not a struct rebuilt from it): `env` is in it as sent, `cut` only on the entries that have it.
  public static func envelopeDigest(_ v: JSONValue) -> String {
    Bytes.sha256Hex(Canonical.bytes(v))
  }

  /// Pending id of a digest: "wd-" + the first 32 hex characters.
  public static func pendingId(digest: String) -> String {
    "wd-" + String(digest.prefix(32))
  }

  public enum CheckFailure: Error, Equatable {
    case notV1
    case otherSupervisor
    case digestMismatch(record: String, computed: String)
    case idMismatch
  }

  /// The check an approver makes before signing an `allow` (protocol/README.md, section 3):
  /// strict envelope, supervisorId equal to the pinned one, digest recomputed, id bound to digest.
  public static func checkPending(id: String, digest: String, envelope: JSONValue?, pinnedSupervisorId: String?) -> Result<ExecEnvelope, CheckFailure> {
    guard let ev = envelope, let env = parseEnvelope(ev) else { return .failure(.notV1) }
    if let pin = pinnedSupervisorId, !sameCodeUnits(env.supervisorId, pin) { return .failure(.otherSupervisor) }
    let d = envelopeDigest(ev)
    guard sameCodeUnits(d, digest) else { return .failure(.digestMismatch(record: String(digest.prefix(12)), computed: String(d.prefix(12)))) }
    guard sameCodeUnits(id, pendingId(digest: d)) else { return .failure(.idMismatch) }
    return .success(env)
  }

  // MARK: signing strings

  /// canonicalJson({type, deviceId, id, digest, decision, ts, nonce[, supervisorId][, risk]}).
  /// `type` is ticketExecType (a wardend record; `supervisorId` = the wardend that queued it,
  /// 64 lowercase hex) or ticketToolType (a gateway plugin tool call, no `supervisorId`), so a
  /// ticket cannot be replayed as the other type or to another wardend.
  public static func decisionSigningString(type: String, deviceId: String, id: String, digest: String, decision: String, ts: Int64, nonce: String,
                                           supervisorId: String? = nil, risk: Int? = nil) -> String {
    Canonical.string(.obj([
      ("type", .string(type)), ("deviceId", .string(deviceId)), ("id", .string(id)), ("digest", .string(digest)), ("decision", .string(decision)),
      ("ts", .int(ts)), ("nonce", .string(nonce)), ("supervisorId", supervisorId.map { .string($0) }), ("risk", risk.map { .int($0) }),
    ]))
  }

  /// canonicalJson({type:"wardenclaw.req.v1", supervisorId, action, deviceId, ts, nonce}): headers of
  /// authenticated requests to wardend, bound to one server by its supervisorId.
  public static func requestSigningString(supervisorId: String, action: String, deviceId: String, ts: Int64, nonce: String) -> String {
    Canonical.string(.obj([
      ("type", .string(reqType)), ("supervisorId", .string(supervisorId)), ("action", .string(action)), ("deviceId", .string(deviceId)),
      ("ts", .int(ts)), ("nonce", .string(nonce)),
    ]))
  }

  /// canonicalJson({type:"wardenclaw.req.v1", supervisorId, action, body, deviceId, ts, nonce}): headers of authenticated requests with a
  /// JSON body (push.register, push.unregister); `body` is exactly the object that is sent.
  public static func requestBodySigningString(supervisorId: String, action: String, deviceId: String, ts: Int64, nonce: String, body: JSONValue) -> String {
    Canonical.string(.obj([
      ("type", .string(reqType)), ("supervisorId", .string(supervisorId)), ("action", .string(action)), ("body", body),
      ("deviceId", .string(deviceId)), ("ts", .int(ts)), ("nonce", .string(nonce)),
    ]))
  }

  /// canonicalJson({type:"wardenclaw.pair.v1", code, deviceId, pubkey, name, supervisorId, ts, nonce[, alg]}).
  /// `alg` is left out for Ed25519 devices (the v1 string); an ES256 device passes "es256".
  public static func pairSigningString(code: String, deviceId: String, pubkey: String, name: String, supervisorId: String, ts: Int64, nonce: String, alg: String? = nil) -> String {
    Canonical.string(.obj([
      ("type", .string(pairType)), ("code", .string(code)), ("deviceId", .string(deviceId)), ("pubkey", .string(pubkey)),
      ("name", .string(name)), ("supervisorId", .string(supervisorId)), ("ts", .int(ts)), ("nonce", .string(nonce)),
      ("alg", alg.map { .string($0) }),
    ]))
  }

  /// The request a response is bound to: its action ("pending", "decide", "pair", "pair.status",
  /// "push.register", …), deviceId and nonce; for decide also the ticket id and digest.
  public struct ResponseContext: Equatable {
    public var action: String
    public var deviceId: String
    public var nonce: String
    public var id: String?
    public var digest: String?
    public init(action: String, deviceId: String, nonce: String, id: String? = nil, digest: String? = nil) {
      self.action = action
      self.deviceId = deviceId
      self.nonce = nonce
      self.id = id
      self.digest = digest
    }
  }

  /// canonicalJson({type:"wardenclaw.resp.v1", action, deviceId, nonce, status, bodySha256[, id, digest]}):
  /// what wardend signs on the response to an authenticated request (id and digest for decide).
  public static func responseSigningString(_ c: ResponseContext, status: Int, body: [UInt8]) -> String {
    let ticket = !(c.id ?? "").isEmpty || !(c.digest ?? "").isEmpty
    return Canonical.string(.obj([
      ("type", .string(respType)), ("action", .string(c.action)), ("deviceId", .string(c.deviceId)), ("nonce", .string(c.nonce)),
      ("status", .int(status)), ("bodySha256", .string(Bytes.sha256Hex(body))),
      ("id", ticket ? .string(c.id ?? "") : nil), ("digest", ticket ? .string(c.digest ?? "") : nil),
    ]))
  }

  /// canonicalJson({type:"wardenclaw.ping.v1", nonce, status, bodySha256}): the response to /v1/ping.
  public static func pingSigningString(nonce: String, status: Int, body: [UInt8]) -> String {
    Canonical.string(.obj([("type", .string(pingType)), ("nonce", .string(nonce)), ("status", .int(status)), ("bodySha256", .string(Bytes.sha256Hex(body)))]))
  }

  /// canonicalJson({type:"wardenclaw.resp.unauth.v1", action, status, bodySha256}): a rejection before the
  /// request was authenticated. Anyone gets one for any request, so it is not an answer to ours.
  public static func unauthSigningString(action: String, status: Int, body: [UInt8]) -> String {
    Canonical.string(.obj([("type", .string(unauthType)), ("action", .string(action)), ("status", .int(status)), ("bodySha256", .string(Bytes.sha256Hex(body)))]))
  }

  /// The signed decide body speaks of our ticket: the same id and, with ok:true, the same decision.
  public static func decideResponseMatches(_ body: JSONValue, id: String, decision: String) -> Bool {
    guard body["id"]?.stringValue == id else { return false }
    return body["ok"]?.boolValue != true || body["decision"]?.stringValue == decision
  }

  /// supervisorId = hex(sha256(raw supervisor public key)).
  public static func supervisorId(keyB64url: String) -> String? {
    guard let raw = Bytes.unb64url(keyB64url), raw.count == 32 else { return nil }
    return Bytes.sha256Hex(raw)
  }

  /// First 16 hex characters of an id in groups of four, as `wardend pair list` shows it.
  public static func fingerprint(_ id: String) -> String {
    let d = Array(id.prefix(16))
    guard d.count == 16 else { return id }
    return [0, 4, 8, 12].map { String(d[$0..<($0 + 4)]) }.joined(separator: " ")
  }

  // MARK: pairing link

  public struct PairLink: Equatable {
    public let url: String
    public let key: String
    public let code: String
    public let host: String
  }

  public enum LinkError: Error, Equatable { case notWardend, version, noAddress, badKey, noCode }

  /// wardenclaw://pair?code=…&host=…&key=…&url=…&v=1 (same rules as parsePairLink in the app).
  public static func parsePairLink(_ input: String) -> Result<PairLink, LinkError> {
    let s = trimSpaces(input)
    let lower = s.lowercased()
    var rest: Substring
    if lower.hasPrefix("wardenclaw://pair/?") {
      rest = s.dropFirst("wardenclaw://pair/?".count)
    } else if lower.hasPrefix("wardenclaw://pair?") {
      rest = s.dropFirst("wardenclaw://pair?".count)
    } else {
      return .failure(.notWardend)
    }
    var q: [String: String] = [:]
    for part in rest.split(separator: "&", omittingEmptySubsequences: true) {
      let kv = part.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
      guard let k = percentDecode(String(kv[0])) else { return .failure(.notWardend) }
      let v = kv.count > 1 ? percentDecode(String(kv[1])) : ""
      guard let val = v else { return .failure(.notWardend) }
      q[k] = val
    }
    rest = ""
    guard q["v"] == "1" else { return .failure(.version) }
    var url = trimSpaces(q["url"] ?? "")
    while url.hasSuffix("/") { url.removeLast() }
    let ul = url.lowercased()
    let scheme = ul.hasPrefix("https://") ? 8 : ul.hasPrefix("http://") ? 7 : 0
    guard scheme > 0, let first = url.dropFirst(scheme).first, first != "/", !first.isWhitespace else { return .failure(.noAddress) }
    let key = trimSpaces(q["key"] ?? "")
    guard let raw = Bytes.unb64url(key), raw.count == 32 else { return .failure(.badKey) }
    let code = normalizeCode(q["code"] ?? "")
    guard code.count >= 6 else { return .failure(.noCode) }
    return .success(PairLink(url: url, key: key, code: code, host: String((q["host"] ?? "").prefix(64))))
  }

  public static func normalizeCode(_ s: String) -> String {
    String(s.filter { $0 != "-" && !$0.isWhitespace }).uppercased()
  }

  static func trimSpaces(_ s: String) -> String {
    var t = Substring(s)
    while let f = t.first, f.isWhitespace { t.removeFirst() }
    while let l = t.last, l.isWhitespace { t.removeLast() }
    return String(t)
  }

  /// decodeURIComponent after `+` → space; nil on a malformed escape or invalid UTF-8.
  static func percentDecode(_ s: String) -> String? {
    var out: [UInt8] = []
    let u = Array(s.utf8)
    var i = 0
    while i < u.count {
      let c = u[i]
      if c == UInt8(ascii: "+") { out.append(0x20); i += 1; continue }
      if c == UInt8(ascii: "%") {
        guard i + 2 < u.count, let b = Bytes.unhex(String(decoding: u[(i + 1)...(i + 2)], as: UTF8.self)) else { return nil }
        out.append(b[0])
        i += 3
        continue
      }
      out.append(c)
      i += 1
    }
    var it = out.makeIterator()
    var dec = UTF8()
    var sv = String.UnicodeScalarView()
    while true {
      switch dec.decode(&it) {
      case let .scalarValue(x): sv.append(x)
      case .emptyInput: return String(sv)
      case .error: return nil
      }
    }
  }

  // MARK: display

  /// One line for the card: the command inside a claude-cli wrapper only on its exact template,
  /// otherwise the `sh -c` script or argv shell-quoted (protocol/DISPLAY.md, Display.swift).
  /// Display only: what is signed is the digest.
  public static func displayCommand(_ argv: [String]) -> String {
    Display.commandView(argv: argv, exe: "", cwd: "", chain: []).command
  }
}

/// Push registration bodies (POST /v1/push/register, /v1/push/unregister). The request is signed
/// over this exact object (requestBodySigningString) and sent as its canonical JSON bytes, so what
/// wardend parses and what the device signed cannot differ.
public enum WatchPush {
  /// Notification category of approval pushes; its actions are only Deny and Open (see WatchApp).
  public static let category = "WARDEN_APPROVAL"

  public static func registerBody(deviceId: String, token: String, topic: String, environment: String) -> JSONValue {
    .obj([("deviceId", .string(deviceId)), ("platform", .string("apns")), ("token", .string(token)), ("topic", .string(topic)), ("environment", .string(environment))])
  }

  public static func unregisterBody(deviceId: String, token: String?) -> JSONValue {
    .obj([("deviceId", .string(deviceId)), ("platform", .string("apns")), ("token", token.map { .string($0) })])
  }
}
