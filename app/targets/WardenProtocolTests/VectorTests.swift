// SPDX-License-Identifier: Apache-2.0
// The Swift protocol code (targets/watch/Protocol) against the shared vectors in protocol/vectors/:
// the same bytes wardend (Go) and the app (TypeScript) are tested with.
//   cd app/targets && swift test
import Foundation
import XCTest
@testable import WardenProtocol
#if canImport(CryptoKit)
import CryptoKit
#endif

private let vectorsDir = URL(fileURLWithPath: #filePath)
  .deletingLastPathComponent() // WardenProtocolTests
  .deletingLastPathComponent() // targets
  .deletingLastPathComponent() // app
  .deletingLastPathComponent() // repository root
  .appendingPathComponent("protocol/vectors")

private func load(_ name: String) throws -> JSONValue {
  let data = try Data(contentsOf: vectorsDir.appendingPathComponent(name))
  return try JSONParser.parse([UInt8](data))
}

private func str(_ v: JSONValue?, _ file: StaticString = #filePath, _ line: UInt = #line) -> String {
  guard let s = v?.stringValue else {
    XCTFail("expected a string", file: file, line: line)
    return ""
  }
  return s
}

private func int(_ v: JSONValue?) -> Int64 { v?.safeInteger ?? -1 }

final class CanonicalVectorTests: XCTestCase {
  func testCanonicalVectorsByteForByte() throws {
    let vf = try load("canonical_vectors.json")
    let cases = try XCTUnwrap(vf["cases"]?.arrayValue)
    XCTAssertGreaterThan(cases.count, 0)
    for c in cases {
      let name = str(c["name"])
      let value = try XCTUnwrap(c["value"])
      XCTAssertEqual(Canonical.string(value), str(c["canonical"]), name)
      XCTAssertEqual(Bytes.sha256Hex(Canonical.bytes(value)), str(c["sha256"]), name)
    }
  }

  func testEnvelopeDigestAndStrictParse() throws {
    let vf = try load("canonical_vectors.json")
    let envs = try XCTUnwrap(vf["cases"]?.arrayValue).filter { $0["envelope"]?.boolValue == true }
    XCTAssertEqual(envs.count, 4)
    var sawCut = false
    for c in envs {
      let v = try XCTUnwrap(c["value"])
      let digest = str(c["sha256"])
      let parsed = WardenProtocol.parseEnvelope(v)
      XCTAssertNotNil(parsed, str(c["name"]))
      // env as sent: the same entries in the same order, cut only where the vector has it
      let wantEnv = try XCTUnwrap(v["env"]?.arrayValue, str(c["name"]))
      XCTAssertEqual(parsed?.env.count, wantEnv.count, str(c["name"]))
      for (g, w) in zip(parsed?.env ?? [], wantEnv) {
        XCTAssertTrue(sameCodeUnits(g.name, str(w["name"])) && sameCodeUnits(g.value, str(w["value"])), str(c["name"]))
        XCTAssertEqual(g.cut, w["cut"]?.safeInteger, str(c["name"]))
        if g.cut != nil { sawCut = true }
      }
      XCTAssertEqual(WardenProtocol.envelopeDigest(v), digest)
      let id = WardenProtocol.pendingId(digest: digest)
      let sup = str(v["requester"]?["supervisorId"])
      switch WardenProtocol.checkPending(id: id, digest: digest, envelope: v, pinnedSupervisorId: sup) {
      case let .success(env): XCTAssertEqual(env.supervisorId, sup)
      case let .failure(f): XCTFail("\(f)")
      }
    }
    XCTAssertTrue(sawCut, "a vector with a cut env value")
  }

  /// Finding 4: env is signed. Changing, dropping or un-cutting an entry changes the digest, and a
  /// malformed entry fails the strict parse (only deny is possible then).
  func testEnvIsSignedAndStrict() throws {
    let vf = try load("canonical_vectors.json")
    let c = try XCTUnwrap(vf["cases"]?.arrayValue?.first { $0["name"]?.stringValue == "envelope-env-loader" })
    let v = try XCTUnwrap(c["value"])
    let digest = str(c["sha256"])
    let id = WardenProtocol.pendingId(digest: digest)
    guard case let .object(m) = v, let ei = m.firstIndex(where: { $0.0 == "env" }), case let .array(entries) = m[ei].1 else { return XCTFail("env") }
    let parsed = try XCTUnwrap(WardenProtocol.parseEnvelope(v))
    XCTAssertEqual(parsed.env.map { $0.name }, ["LD_PRELOAD", "GIT_SSH_COMMAND", "LD_PRELOAD", "PYTHONPATH"])
    XCTAssertEqual(parsed.env.map { $0.cut }, [nil, nil, nil, 5])
    XCTAssertEqual(parsed.env[3].value.unicodeScalars.count, WardenProtocol.envValueMax)

    func with(_ env: JSONValue?) -> JSONValue {
      var o = m
      if let e = env { o[ei].1 = e } else { o.remove(at: ei) }
      return .object(o)
    }
    func entry(_ members: [(String, JSONValue)]) -> JSONValue { .object(members) }
    // the digest covers env: another value, a dropped entry, a dropped cut, another order
    var changed = entries
    changed[2] = entry([("name", .string("LD_PRELOAD")), ("value", .string("/tmp/y.so"))])
    var noCut = entries
    guard case var .object(last) = noCut[3] else { return XCTFail("entry") }
    last.removeAll { $0.0 == "cut" }
    noCut[3] = .object(last)
    for bad in [changed, Array(entries.dropLast()), noCut, Array(entries.reversed()), []] {
      let ev = with(.array(bad))
      XCTAssertNotNil(WardenProtocol.parseEnvelope(ev))
      if case .digestMismatch = WardenProtocol.checkPending(id: id, digest: digest, envelope: ev, pinnedSupervisorId: nil).failure {} else { XCTFail("digest must cover env") }
    }
    // strict shape: env present and an array, entries exactly {name,value} or {name,value,cut}
    XCTAssertNil(WardenProtocol.parseEnvelope(with(nil)), "env missing (13 fields)")
    XCTAssertEqual(WardenProtocol.checkPending(id: id, digest: digest, envelope: with(nil), pinnedSupervisorId: nil).failure, .notV1)
    for notArray: JSONValue in [.null, .string("HOME=/root"), .object([]), .int(0)] {
      XCTAssertNil(WardenProtocol.parseEnvelope(with(notArray)), "env \(notArray)")
    }
    let long = String(repeating: "a", count: WardenProtocol.envValueMax + 1)
    let badEntries: [JSONValue] = [
      .string("LD_PRELOAD=/tmp/x.so"),
      .null,
      entry([("name", .string("A"))]),
      entry([("value", .string("x"))]),
      entry([("name", .string("A")), ("value", .string("x")), ("extra", .int(1))]),
      entry([("name", .string("A")), ("value", .string("x")), ("cut", .int(1)), ("extra", .int(1))]),
      entry([("name", .string("A")), ("value", .string("x")), ("cut", .int(0))]),
      entry([("name", .string("A")), ("value", .string("x")), ("cut", .int(-3))]),
      entry([("name", .string("A")), ("value", .string("x")), ("cut", .number(1.5))]),
      entry([("name", .string("A")), ("value", .string("x")), ("cut", .string("5"))]),
      entry([("name", .string("A")), ("value", .string("x")), ("cut", .null)]),
      entry([("name", .string("")), ("value", .string("x"))]),
      entry([("name", .string("A=B")), ("value", .string("x"))]),
      entry([("name", .int(1)), ("value", .string("x"))]),
      entry([("name", .string("A")), ("value", .null)]),
      entry([("name", .string("A")), ("value", .array([]))]),
      entry([("name", .string("A")), ("value", .string(long))]),
      entry([("Name", .string("A")), ("value", .string("x"))]),
    ]
    for (i, b) in badEntries.enumerated() {
      XCTAssertNil(WardenProtocol.parseEnvelope(with(.array(entries + [b]))), "bad env entry \(i)")
    }
    // at the limit: 1024 code points (an emoji is two UTF-16 units, four UTF-8 bytes), "=" in the value
    let atLimit = String(repeating: "😀", count: WardenProtocol.envValueMax)
    let good = with(.array([entry([("name", .string("X")), ("value", .string(atLimit)), ("cut", .int(7))]),
                            entry([("name", .string("GIT_CONFIG_PARAMETERS")), ("value", .string("'a=b'"))]),
                            entry([("name", .string("E")), ("value", .string(""))])]))
    let g = try XCTUnwrap(WardenProtocol.parseEnvelope(good))
    XCTAssertEqual(g.env.map { $0.cut }, [7, nil, nil])
  }

  /// envView (DISPLAY.md 7a) on the finding-4 vector: a harmless command with LD_PRELOAD makes the card dangerous.
  func testEnvView() throws {
    let vf = try load("canonical_vectors.json")
    let c = try XCTUnwrap(vf["cases"]?.arrayValue?.first { $0["name"]?.stringValue == "envelope-env-loader" })
    let env = try XCTUnwrap(WardenProtocol.parseEnvelope(try XCTUnwrap(c["value"]))).env
    let ev = Display.envView(env)
    XCTAssertEqual(ev.entries.map { $0.flags }, [["duplicate"], [], ["duplicate"], ["truncated"]])
    XCTAssertEqual(ev.entries.map { $0.loader }, [true, false, true, false])
    XCTAssertEqual(ev.entries.map { $0.cut }, [0, 0, 0, 5])
    XCTAssertEqual(ev.loader, ["LD_PRELOAD"])
    XCTAssertTrue(ev.dangerous)
    XCTAssertFalse(Display.commandView(argv: ["ls", "-la"], exe: "/usr/bin/ls", cwd: "", chain: []).dangerous, "a harmless command: only env makes it dangerous")

    XCTAssertEqual(Display.envView([]), Display.EnvView.empty)
    let plain = Display.envView([.init(name: "HOME", value: "/home/u"), .init(name: "LD_PRELOAD", value: ""), .init(name: "ld_preload", value: "/x.so")])
    XCTAssertFalse(plain.dangerous, "an empty LD_PRELOAD and a lowercase name load nothing")
    XCTAssertEqual(plain.loader, [])
    let odd = Display.envView([.init(name: "LD_AUDIT", value: "/a.so"), .init(name: "B\u{1}", value: "x\u{202E}y\u{200B}", cut: 3), .init(name: "LD_LIBRARY_PATH", value: "/l"),
                               .init(name: "\u{e9}", value: "1"), .init(name: "e\u{301}", value: "2")])
    XCTAssertEqual(odd.loader, ["LD_AUDIT", "LD_LIBRARY_PATH"])
    XCTAssertEqual(odd.entries[1].flags, ["control", "bidi", "invisible", "truncated"])
    XCTAssertTrue(sameCodeUnits(odd.entries[1].name, "B⟨U+0001⟩"))
    XCTAssertTrue(sameCodeUnits(odd.entries[1].value, "x⟨U+202E⟩y⟨U+200B⟩"))
    XCTAssertEqual(odd.entries[3].flags, [], "names compare by code units, not canonical equivalence")
    XCTAssertEqual(odd.entries[4].flags, [])
  }

  /// display_vectors.json, key `env`: [{input: env, expect: envView(env)}] from app/src/core/display.ts.
  func testEnvDisplayVectors() throws {
    let dv = try load("display_vectors.json")
    let cases = try XCTUnwrap(dv["env"]?.arrayValue, "display_vectors.json has no env key")
    XCTAssertGreaterThan(cases.count, 0)
    for (k, c) in cases.enumerated() {
      let name = c["name"]?.stringValue ?? "env case \(k)"
      let input = try XCTUnwrap(c["input"]?.arrayValue, name).map { e in
        WardenProtocol.EnvVar(name: e["name"]?.stringValue ?? "", value: e["value"]?.stringValue ?? "", cut: e["cut"]?.safeInteger)
      }
      let e = try XCTUnwrap(c["expect"], name)
      let got = Display.envView(input)
      let want = e["entries"]?.arrayValue ?? []
      XCTAssertEqual(got.entries.count, want.count, name)
      for (g, w) in zip(got.entries, want) {
        XCTAssertTrue(sameCodeUnits(g.name, w["name"]?.stringValue ?? "?"), "\(name): name \(g.name.debugDescription)")
        XCTAssertTrue(sameCodeUnits(g.value, w["value"]?.stringValue ?? "?"), "\(name): value \(g.value.debugDescription)")
        XCTAssertEqual(g.cut, w["cut"]?.safeInteger ?? 0, "\(name): cut")
        XCTAssertEqual(g.flags, w["flags"]?.arrayValue?.compactMap { $0.stringValue } ?? [], "\(name): flags of \(g.name)")
        XCTAssertEqual(g.loader, w["loader"]?.boolValue ?? false, "\(name): loader of \(g.name)")
      }
      XCTAssertEqual(got.loader, e["loader"]?.arrayValue?.compactMap { $0.stringValue } ?? [], "\(name): loader")
      XCTAssertEqual(got.dangerous, e["dangerous"]?.boolValue, "\(name): dangerous")
    }
  }

  func testCheckPendingRejects() throws {
    let vf = try load("canonical_vectors.json")
    let c = try XCTUnwrap(vf["cases"]?.arrayValue?.first { $0["envelope"]?.boolValue == true })
    let v = try XCTUnwrap(c["value"])
    let digest = str(c["sha256"])
    let id = WardenProtocol.pendingId(digest: digest)
    guard case var .object(m) = v else { return XCTFail("object") }

    // another supervisor
    XCTAssertEqual(WardenProtocol.checkPending(id: id, digest: digest, envelope: v, pinnedSupervisorId: String(repeating: "0", count: 64)).failure, .otherSupervisor)
    // id not bound to the digest
    XCTAssertEqual(WardenProtocol.checkPending(id: "wd-" + String(repeating: "0", count: 32), digest: digest, envelope: v, pinnedSupervisorId: nil).failure, .idMismatch)
    // a changed field changes the digest
    var changed = m
    changed[changed.firstIndex { $0.0 == "argv" }!].1 = .array([.string("ls")])
    if case .digestMismatch = WardenProtocol.checkPending(id: id, digest: digest, envelope: .object(changed), pinnedSupervisorId: nil).failure {} else { XCTFail("digest") }
    // strict shape: extra field, v:2, a float uid, a missing field
    m.append(("extra", .int(1)))
    XCTAssertEqual(WardenProtocol.checkPending(id: id, digest: digest, envelope: .object(m), pinnedSupervisorId: nil).failure, .notV1)
    m.removeLast()
    var v2 = m
    v2[v2.firstIndex { $0.0 == "v" }!].1 = .int(2)
    XCTAssertNil(WardenProtocol.parseEnvelope(.object(v2)))
    var fl = m
    fl[fl.firstIndex { $0.0 == "uid" }!].1 = .number(1000.5)
    XCTAssertNil(WardenProtocol.parseEnvelope(.object(fl)))
    XCTAssertNil(WardenProtocol.parseEnvelope(.object(Array(m.dropFirst()))))
    XCTAssertNotNil(WardenProtocol.parseEnvelope(.object(m)))
  }

  func testNumbers() {
    let cases: [(Double, String)] = [
      (0, "0"), (-0.0, "0"), (-1, "-1"), (1.5, "1.5"), (1e21, "1e+21"), (1e-7, "1e-7"), (123456789012345, "123456789012345"),
      (0.000001, "0.000001"), (2e-7, "2e-7"), (1.7976931348623157e308, "1.7976931348623157e+308"), (5e-324, "5e-324"),
      (100, "100"), (1e20, "100000000000000000000"), (-0.5, "-0.5"), (0.1, "0.1"), (1790447985039, "1790447985039"),
      (123.456, "123.456"), (1.5e-10, "1.5e-10"), (2.5e25, "2.5e+25"), (9007199254740992, "9007199254740992"),
      (Double.infinity, "null"), (Double.nan, "null"),
    ]
    for (d, s) in cases { XCTAssertEqual(Canonical.ecmaNumberString(d), s, "\(d)") }
  }

  func testParserIsStrict() {
    for bad in ["", "{", "[1,]", "{\"a\":1,}", "01", "1.", ".5", "+1", "\"\\x\"", "\"\\ud800\"", "\"\\udc00x\"", "{} x", "tru", "\"a\u{1}\"", "NaN"] {
      XCTAssertThrowsError(try JSONParser.parse(bad), bad)
    }
    XCTAssertThrowsError(try JSONParser.parse([0x22, 0xC3, 0x28, 0x22]), "invalid UTF-8")
    XCTAssertThrowsError(try JSONParser.parse([0x22, 0xED, 0xA0, 0x80, 0x22]), "UTF-8 encoded surrogate")
    XCTAssertEqual(try JSONParser.parse("\"\\ud83d\\ude00\""), .string("😀"))
    // duplicate keys: the last value wins (JSON.parse); keys compare by code units, not by Unicode equivalence
    XCTAssertEqual(Canonical.string(try JSONParser.parse("{\"a\":1,\"a\":2}")), "{\"a\":2}")
    XCTAssertEqual(Canonical.string(try JSONParser.parse("{\"\\u00e9\":1,\"e\\u0301\":2}")), "{\"e\u{301}\":2,\"\u{e9}\":1}")
  }

  func testDisplayCommand() {
    // only the exact claude-cli template is folded; an eval anywhere else shows the whole script
    let wrap = "source /home/u/.claude/shell-snapshots/snapshot-bash-1790452891926-09cuz2.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval 'ls -la /tmp && echo '\"'\"'hi'\"'\"'' < /dev/null && pwd -P >| /tmp/claude-ab12-cwd"
    XCTAssertEqual(WardenProtocol.displayCommand(["/bin/bash", "-c", wrap]), "ls -la /tmp && echo 'hi'")
    let fake = "source /x/snap.sh 2>/dev/null || true && eval 'ls -la /tmp' < /dev/null && pwd -P >| /tmp/cwd"
    XCTAssertEqual(WardenProtocol.displayCommand(["/bin/bash", "-c", fake]), fake)
    XCTAssertEqual(WardenProtocol.displayCommand(["ls", "-la", "a b"]), "ls -la 'a b'")
    XCTAssertEqual(WardenProtocol.displayCommand(["sh", "-c", "echo 1"]), "echo 1")
  }
}

final class SigningVectorTests: XCTestCase {
  func testHardwareVectorsSigningStrings() throws {
    let hv = try load("hw_vectors.json")
    for c in try XCTUnwrap(hv["cases"]?.arrayValue) {
      let p = try XCTUnwrap(c["payload"])
      let risk = p["risk"]?.safeInteger.map { Int($0) }
      let type = str(p["type"])
      XCTAssertEqual(type, WardenProtocol.ticketExecType)
      let s = WardenProtocol.decisionSigningString(type: type, deviceId: str(c["deviceId"]), id: str(p["id"]), digest: str(p["digest"]), decision: str(p["decision"]), ts: int(p["ts"]), nonce: str(p["nonce"]), supervisorId: p["supervisorId"]?.stringValue, risk: risk)
      XCTAssertEqual(s, str(c["signingString"]), str(c["name"]))
    }
  }

  /// Identities are hashes of raw public keys; the fingerprint is the first 16 hex characters
  /// of an id in groups of four (protocol/README.md). Fixed keys, no vector file.
  func testIdsAndFingerprint() throws {
    let deviceId = "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9"
    let devicePubkey = try XCTUnwrap(Bytes.unb64url("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"))
    XCTAssertEqual(Bytes.sha256Hex(devicePubkey), deviceId)
    XCTAssertEqual(WardenProtocol.fingerprint(deviceId), "21fe 31df a154 a261")
    XCTAssertEqual(WardenProtocol.supervisorId(keyB64url: "PUAXw-hDiVqStwqnTRt-vJyYLM8uxJaMwM1V8Sr0Zgw"), "39f713d0a644253f04529421b9f51b9b08979d08295959c4f3990ee617f5139f")
    XCTAssertNil(WardenProtocol.supervisorId(keyB64url: "abc"))
  }

  /// es256_vectors.json: the Apple Watch device (P-256). Written by the wardend side; skipped if absent.
  func testES256Vectors() throws {
    let url = vectorsDir.appendingPathComponent("es256_vectors.json")
    guard FileManager.default.fileExists(atPath: url.path) else { throw XCTSkip("protocol/vectors/es256_vectors.json not present") }
    let ev = try load("es256_vectors.json")
    let deviceId = str(ev["deviceId"])
    let pub = try XCTUnwrap(Bytes.unb64url(str(ev["publicKeySEC1"])))
    XCTAssertEqual(pub.count, 65)
    XCTAssertEqual(pub[0], 0x04)
    XCTAssertEqual(Bytes.sha256Hex(pub), deviceId, "deviceId = hex(sha256(SEC1 uncompressed))")

    let pp = try XCTUnwrap(ev["pair"]?["payload"])
    let pairS = WardenProtocol.pairSigningString(code: str(pp["code"]), deviceId: str(pp["deviceId"]), pubkey: str(pp["pubkey"]), name: str(pp["name"]), supervisorId: str(pp["supervisorId"]), ts: int(pp["ts"]), nonce: str(pp["nonce"]), alg: str(pp["alg"]))
    XCTAssertEqual(pairS, str(ev["pair"]?["signingString"]))
    XCTAssertEqual(WardenProtocol.fingerprint(deviceId), str(ev["pair"]?["fingerprint"]))

    var checked: [(String, String, String)] = [(str(ev["pair"]?["signingString"]), str(ev["pair"]?["signatureRaw"]), str(ev["pair"]?["signatureDER"]))]
    for t in try XCTUnwrap(ev["tickets"]?.arrayValue) {
      let p = try XCTUnwrap(t["payload"])
      let type = str(p["type"])
      XCTAssertEqual(type, WardenProtocol.ticketExecType)
      let s = WardenProtocol.decisionSigningString(type: type, deviceId: deviceId, id: str(p["id"]), digest: str(p["digest"]), decision: str(p["decision"]), ts: int(p["ts"]), nonce: str(p["nonce"]), supervisorId: p["supervisorId"]?.stringValue, risk: p["risk"]?.safeInteger.map { Int($0) })
      XCTAssertEqual(s, str(t["signingString"]), str(t["name"]))
      checked.append((s, str(t["signatureRaw"]), str(t["signatureDER"])))
    }

    #if canImport(CryptoKit)
    // CryptoKit (what the watch's Secure Enclave key produces) verifies the reference signatures,
    // and its own raw r||s output is 64 bytes.
    let key = try P256.Signing.PublicKey(x963Representation: pub)
    for (s, raw, der) in checked {
      let msg = Array(s.utf8)
      XCTAssertTrue(key.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: Bytes.unb64url(raw)!), for: msg))
      XCTAssertTrue(key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: Bytes.unb64url(der)!), for: msg))
    }
    let sk = P256.Signing.PrivateKey()
    let sig = try sk.signature(for: Array(checked[0].0.utf8))
    XCTAssertEqual(sig.rawRepresentation.count, 64)
    XCTAssertEqual(sk.publicKey.x963Representation.count, 65)
    #endif
  }
}

private extension Result {
  var failure: Failure? {
    if case let .failure(f) = self { return f }
    return nil
  }
}
