// SPDX-License-Identifier: Apache-2.0
// WardenClaw protocol v1 in Swift: a JSON value, a strict parser and canonical JSON.
//
// canonicalJson must be byte-identical to the JavaScript reference (protocol/README.md, section 2):
//   - object keys sorted by UTF-16 code units (Array.prototype.sort), not by Swift String order;
//   - strings escape only `"`, `\` and characters below U+0020 (\b \t \n \f \r, the rest \u00xx);
//   - numbers formatted as ECMAScript Number::toString;
//   - no whitespace.
// Swift String equality is canonical-equivalence ("e\u{301}" == "\u{e9}"), JavaScript compares
// code units. Everything here that compares keys or protocol strings therefore compares UTF-16 or
// UTF-8 code units explicitly.
//
// Pure Swift plus Foundation-free standard library: the same file compiles for watchOS, iOS,
// macOS and Linux (the tests in Tests/ run on all of them).

public enum JSONValue: Equatable {
  case null
  case bool(Bool)
  case number(Double)
  case string(String)
  case array([JSONValue])
  /// Members in document order, keys unique (a duplicate key keeps the last value, as JSON.parse).
  case object([(String, JSONValue)])

  public static func == (a: JSONValue, b: JSONValue) -> Bool {
    switch (a, b) {
    case (.null, .null): return true
    case let (.bool(x), .bool(y)): return x == y
    case let (.number(x), .number(y)): return x == y
    case let (.string(x), .string(y)): return sameCodeUnits(x, y)
    case let (.array(x), .array(y)): return x == y
    case let (.object(x), .object(y)):
      guard x.count == y.count else { return false }
      for (k, v) in x {
        guard let w = JSONValue.member(y, k), w == v else { return false }
      }
      return true
    default: return false
    }
  }

  static func member(_ members: [(String, JSONValue)], _ key: String) -> JSONValue? {
    for (k, v) in members where sameCodeUnits(k, key) { return v }
    return nil
  }

  /// Object member by exact key (code units), nil if absent or not an object.
  public subscript(key: String) -> JSONValue? {
    if case let .object(m) = self { return JSONValue.member(m, key) }
    return nil
  }

  public var stringValue: String? {
    if case let .string(s) = self { return s }
    return nil
  }

  public var arrayValue: [JSONValue]? {
    if case let .array(a) = self { return a }
    return nil
  }

  public var objectMembers: [(String, JSONValue)]? {
    if case let .object(m) = self { return m }
    return nil
  }

  public var boolValue: Bool? {
    if case let .bool(b) = self { return b }
    return nil
  }

  public var doubleValue: Double? {
    if case let .number(d) = self { return d }
    return nil
  }

  /// Number.isSafeInteger: integral and |x| <= 2^53 - 1.
  public var safeInteger: Int64? {
    guard case let .number(d) = self, d.isFinite, d == d.rounded(.towardZero), abs(d) <= 9_007_199_254_740_991 else { return nil }
    return Int64(d)
  }

  /// Build an object from members; nil values are left out (JavaScript `undefined`).
  public static func obj(_ members: [(String, JSONValue?)]) -> JSONValue {
    var out: [(String, JSONValue)] = []
    for (k, v) in members {
      guard let v = v else { continue }
      if let i = out.firstIndex(where: { sameCodeUnits($0.0, k) }) { out[i].1 = v } else { out.append((k, v)) }
    }
    return .object(out)
  }

  public static func int(_ i: Int64) -> JSONValue { .number(Double(i)) }
  public static func int(_ i: Int) -> JSONValue { .number(Double(i)) }
}

/// Exact code-unit equality, the way JavaScript `===` compares strings.
public func sameCodeUnits(_ a: String, _ b: String) -> Bool {
  a.utf8.elementsEqual(b.utf8)
}

/// Array.prototype.sort() order: lexicographic over UTF-16 code units.
@inline(__always) func utf16Less(_ a: String, _ b: String) -> Bool {
  a.utf16.lexicographicallyPrecedes(b.utf16)
}

// MARK: - canonical JSON

public enum Canonical {
  /// canonicalJson(v) as UTF-8 bytes.
  public static func bytes(_ v: JSONValue) -> [UInt8] {
    var out: [UInt8] = []
    out.reserveCapacity(256)
    write(v, &out)
    return out
  }

  /// canonicalJson(v) as a String.
  public static func string(_ v: JSONValue) -> String {
    String(decoding: bytes(v), as: UTF8.self)
  }

  static func write(_ v: JSONValue, _ out: inout [UInt8]) {
    switch v {
    case .null: out.append(contentsOf: Array("null".utf8))
    case let .bool(b): out.append(contentsOf: Array((b ? "true" : "false").utf8))
    case let .number(d): out.append(contentsOf: Array(ecmaNumberString(d).utf8))
    case let .string(s): writeString(s, &out)
    case let .array(a):
      out.append(UInt8(ascii: "["))
      for (i, x) in a.enumerated() {
        if i > 0 { out.append(UInt8(ascii: ",")) }
        write(x, &out)
      }
      out.append(UInt8(ascii: "]"))
    case let .object(m):
      out.append(UInt8(ascii: "{"))
      let sorted = m.sorted { utf16Less($0.0, $1.0) }
      for (i, kv) in sorted.enumerated() {
        if i > 0 { out.append(UInt8(ascii: ",")) }
        writeString(kv.0, &out)
        out.append(UInt8(ascii: ":"))
        write(kv.1, &out)
      }
      out.append(UInt8(ascii: "}"))
    }
  }

  static let hex: [UInt8] = Array("0123456789abcdef".utf8)

  /// JSON.stringify(string): escapes only `"`, `\` and U+0000..U+001F.
  static func writeString(_ s: String, _ out: inout [UInt8]) {
    out.append(UInt8(ascii: "\""))
    for u in s.unicodeScalars {
      switch u.value {
      case 0x22: out.append(contentsOf: [0x5C, 0x22])
      case 0x5C: out.append(contentsOf: [0x5C, 0x5C])
      case 0x08: out.append(contentsOf: [0x5C, UInt8(ascii: "b")])
      case 0x09: out.append(contentsOf: [0x5C, UInt8(ascii: "t")])
      case 0x0A: out.append(contentsOf: [0x5C, UInt8(ascii: "n")])
      case 0x0C: out.append(contentsOf: [0x5C, UInt8(ascii: "f")])
      case 0x0D: out.append(contentsOf: [0x5C, UInt8(ascii: "r")])
      case 0..<0x20:
        out.append(contentsOf: [0x5C, UInt8(ascii: "u"), UInt8(ascii: "0"), UInt8(ascii: "0"), hex[Int(u.value >> 4)], hex[Int(u.value & 0xF)]])
      default:
        UTF8.encode(u) { out.append($0) }
      }
    }
    out.append(UInt8(ascii: "\""))
  }

  /// ECMAScript Number::toString(10) (what JSON.stringify prints); NaN and ±Infinity become null.
  public static func ecmaNumberString(_ d: Double) -> String {
    if !d.isFinite { return "null" }
    if d == 0 { return "0" } // also -0
    let neg = d < 0
    // Swift's description is the shortest round-trip digit string (the same digits ECMAScript
    // requires); only the layout differs, so take the digits and the exponent and re-layout.
    var desc = Substring(abs(d).description)
    var exp10 = 0
    if let e = desc.firstIndex(where: { $0 == "e" || $0 == "E" }) {
      exp10 = Int(desc[desc.index(after: e)...].replacingPlus()) ?? 0
      desc = desc[..<e]
    }
    var digits: [UInt8] = []
    var fracLen = 0
    var seenDot = false
    for c in desc.utf8 {
      if c == UInt8(ascii: ".") { seenDot = true; continue }
      digits.append(c)
      if seenDot { fracLen += 1 }
    }
    // value = digits × 10^(exp10 - fracLen)
    var power = exp10 - fracLen
    while let f = digits.first, f == UInt8(ascii: "0"), digits.count > 1 { digits.removeFirst() }
    while let l = digits.last, l == UInt8(ascii: "0"), digits.count > 1 { digits.removeLast(); power += 1 }
    let k = digits.count
    let n = power + k // value = 0.d1d2…dk × 10^n
    var s = ""
    let ds = String(decoding: digits, as: UTF8.self)
    if k <= n && n <= 21 {
      s = ds + String(repeating: "0", count: n - k)
    } else if 0 < n && n <= 21 {
      s = String(ds.prefix(n)) + "." + String(ds.dropFirst(n))
    } else if -6 < n && n <= 0 {
      s = "0." + String(repeating: "0", count: -n) + ds
    } else {
      let e = n - 1
      let es = e < 0 ? "-\(-e)" : "+\(e)"
      s = k == 1 ? ds + "e" + es : String(ds.prefix(1)) + "." + String(ds.dropFirst(1)) + "e" + es
    }
    return neg ? "-" + s : s
  }
}

private extension Substring {
  func replacingPlus() -> Substring { first == "+" ? dropFirst() : self }
}

// MARK: - parser (JSON.parse semantics, strict RFC 8259 grammar)

public struct JSONParseError: Error, CustomStringConvertible {
  public let offset: Int
  public let message: String
  public var description: String { "JSON: \(message) at byte \(offset)" }
}

public enum JSONParser {
  /// Parse UTF-8 bytes. Invalid UTF-8, lone surrogates and trailing garbage are errors (fail closed).
  public static func parse<C: Collection>(_ bytes: C, maxDepth: Int = 64) throws -> JSONValue where C.Element == UInt8 {
    var p = Parser(bytes: Array(bytes), maxDepth: maxDepth)
    p.skipWS()
    let v = try p.value(depth: 0)
    p.skipWS()
    if p.i != p.b.count { throw p.err("trailing data") }
    return v
  }

  public static func parse(_ s: String) throws -> JSONValue {
    try parse(Array(s.utf8))
  }
}

private struct Parser {
  let b: [UInt8]
  let maxDepth: Int
  var i = 0

  init(bytes: [UInt8], maxDepth: Int) {
    b = bytes
    self.maxDepth = maxDepth
  }

  func err(_ m: String) -> JSONParseError { JSONParseError(offset: i, message: m) }

  mutating func skipWS() {
    while i < b.count, b[i] == 0x20 || b[i] == 0x09 || b[i] == 0x0A || b[i] == 0x0D { i += 1 }
  }

  mutating func lit(_ s: String, _ v: JSONValue) throws -> JSONValue {
    let u = Array(s.utf8)
    guard i + u.count <= b.count, Array(b[i..<(i + u.count)]) == u else { throw err("bad literal") }
    i += u.count
    return v
  }

  mutating func value(depth: Int) throws -> JSONValue {
    guard depth <= maxDepth else { throw err("too deep") }
    guard i < b.count else { throw err("unexpected end") }
    switch b[i] {
    case UInt8(ascii: "{"): return try object(depth: depth)
    case UInt8(ascii: "["): return try array(depth: depth)
    case UInt8(ascii: "\""): return .string(try string())
    case UInt8(ascii: "t"): return try lit("true", .bool(true))
    case UInt8(ascii: "f"): return try lit("false", .bool(false))
    case UInt8(ascii: "n"): return try lit("null", .null)
    default: return .number(try number())
    }
  }

  mutating func object(depth: Int) throws -> JSONValue {
    i += 1
    var members: [(String, JSONValue)] = []
    skipWS()
    if i < b.count, b[i] == UInt8(ascii: "}") { i += 1; return .object(members) }
    while true {
      skipWS()
      guard i < b.count, b[i] == UInt8(ascii: "\"") else { throw err("expected key") }
      let k = try string()
      skipWS()
      guard i < b.count, b[i] == UInt8(ascii: ":") else { throw err("expected ':'") }
      i += 1
      skipWS()
      let v = try value(depth: depth + 1)
      if let j = members.firstIndex(where: { sameCodeUnits($0.0, k) }) { members[j].1 = v } else { members.append((k, v)) }
      skipWS()
      guard i < b.count else { throw err("unexpected end") }
      if b[i] == UInt8(ascii: ",") { i += 1; continue }
      if b[i] == UInt8(ascii: "}") { i += 1; return .object(members) }
      throw err("expected ',' or '}'")
    }
  }

  mutating func array(depth: Int) throws -> JSONValue {
    i += 1
    var out: [JSONValue] = []
    skipWS()
    if i < b.count, b[i] == UInt8(ascii: "]") { i += 1; return .array(out) }
    while true {
      skipWS()
      out.append(try value(depth: depth + 1))
      skipWS()
      guard i < b.count else { throw err("unexpected end") }
      if b[i] == UInt8(ascii: ",") { i += 1; continue }
      if b[i] == UInt8(ascii: "]") { i += 1; return .array(out) }
      throw err("expected ',' or ']'")
    }
  }

  mutating func hex4() throws -> UInt32 {
    guard i + 4 <= b.count else { throw err("short \\u escape") }
    var v: UInt32 = 0
    for _ in 0..<4 {
      let c = b[i]
      let d: UInt32
      switch c {
      case 0x30...0x39: d = UInt32(c - 0x30)
      case 0x41...0x46: d = UInt32(c - 0x41 + 10)
      case 0x61...0x66: d = UInt32(c - 0x61 + 10)
      default: throw err("bad hex digit")
      }
      v = v << 4 | d
      i += 1
    }
    return v
  }

  mutating func string() throws -> String {
    i += 1 // opening quote
    var raw: [UInt8] = []
    while true {
      guard i < b.count else { throw err("unterminated string") }
      let c = b[i]
      if c == UInt8(ascii: "\"") { i += 1; break }
      if c < 0x20 { throw err("control character in string") }
      if c != UInt8(ascii: "\\") { raw.append(c); i += 1; continue }
      i += 1
      guard i < b.count else { throw err("unterminated escape") }
      let e = b[i]
      i += 1
      switch e {
      case UInt8(ascii: "\""): raw.append(0x22)
      case UInt8(ascii: "\\"): raw.append(0x5C)
      case UInt8(ascii: "/"): raw.append(0x2F)
      case UInt8(ascii: "b"): raw.append(0x08)
      case UInt8(ascii: "f"): raw.append(0x0C)
      case UInt8(ascii: "n"): raw.append(0x0A)
      case UInt8(ascii: "r"): raw.append(0x0D)
      case UInt8(ascii: "t"): raw.append(0x09)
      case UInt8(ascii: "u"):
        var cp = try hex4()
        if (0xD800...0xDBFF).contains(cp) {
          // must be followed by a low surrogate; a lone surrogate cannot be a Swift String
          guard i + 1 < b.count, b[i] == UInt8(ascii: "\\"), b[i + 1] == UInt8(ascii: "u") else { throw err("lone surrogate") }
          i += 2
          let lo = try hex4()
          guard (0xDC00...0xDFFF).contains(lo) else { throw err("lone surrogate") }
          cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
        } else if (0xDC00...0xDFFF).contains(cp) {
          throw err("lone surrogate")
        }
        guard let sc = Unicode.Scalar(cp) else { throw err("bad code point") }
        UTF8.encode(sc) { raw.append($0) }
      default: throw err("bad escape")
      }
    }
    return try validUTF8(raw)
  }

  func validUTF8(_ raw: [UInt8]) throws -> String {
    var it = raw.makeIterator()
    var dec = UTF8()
    var sv = String.UnicodeScalarView()
    loop: while true {
      switch dec.decode(&it) {
      case let .scalarValue(s): sv.append(s)
      case .emptyInput: break loop
      case .error: throw err("invalid UTF-8")
      }
    }
    return String(sv)
  }

  mutating func number() throws -> Double {
    let start = i
    if i < b.count, b[i] == UInt8(ascii: "-") { i += 1 }
    guard i < b.count else { throw err("bad number") }
    if b[i] == UInt8(ascii: "0") {
      i += 1
    } else if (0x31...0x39).contains(b[i]) {
      while i < b.count, (0x30...0x39).contains(b[i]) { i += 1 }
    } else {
      throw err("unexpected character")
    }
    if i < b.count, b[i] == UInt8(ascii: ".") {
      i += 1
      let s = i
      while i < b.count, (0x30...0x39).contains(b[i]) { i += 1 }
      if i == s { throw err("bad fraction") }
    }
    if i < b.count, b[i] == UInt8(ascii: "e") || b[i] == UInt8(ascii: "E") {
      i += 1
      if i < b.count, b[i] == UInt8(ascii: "+") || b[i] == UInt8(ascii: "-") { i += 1 }
      let s = i
      while i < b.count, (0x30...0x39).contains(b[i]) { i += 1 }
      if i == s { throw err("bad exponent") }
    }
    // Double(String) is correctly rounded, like ECMAScript StringToNumber; overflow gives ±inf
    guard let d = Double(String(decoding: b[start..<i], as: UTF8.self)) else { throw err("bad number") }
    return d
  }
}
