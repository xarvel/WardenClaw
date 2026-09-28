// SPDX-License-Identifier: Apache-2.0
// Byte helpers of the protocol: SHA-256, lowercase hex, base64url without padding.
// On Apple platforms SHA-256 is CryptoKit; elsewhere (Linux, where the tests also run) a small
// FIPS 180-4 implementation checked against the same vectors.
#if canImport(CryptoKit)
import CryptoKit
import Foundation // Array<UInt8>: DataProtocol for SHA256.hash(data:)
#endif

public enum Bytes {
  public static func sha256(_ data: [UInt8]) -> [UInt8] {
    #if canImport(CryptoKit)
    return Array(SHA256.hash(data: data))
    #else
    return SoftSHA256.hash(data)
    #endif
  }

  public static func sha256(_ s: String) -> [UInt8] { sha256(Array(s.utf8)) }

  public static func sha256Hex(_ data: [UInt8]) -> String { hex(sha256(data)) }

  public static func hex(_ b: [UInt8]) -> String {
    let d = Array("0123456789abcdef".utf8)
    var out: [UInt8] = []
    out.reserveCapacity(b.count * 2)
    for x in b {
      out.append(d[Int(x >> 4)])
      out.append(d[Int(x & 0xF)])
    }
    return String(decoding: out, as: UTF8.self)
  }

  /// Lowercase or uppercase hex, even length; nil otherwise.
  public static func unhex(_ s: String) -> [UInt8]? {
    let u = Array(s.utf8)
    guard u.count % 2 == 0 else { return nil }
    func nib(_ c: UInt8) -> UInt8? {
      switch c {
      case 0x30...0x39: return c - 0x30
      case 0x41...0x46: return c - 0x41 + 10
      case 0x61...0x66: return c - 0x61 + 10
      default: return nil
      }
    }
    var out: [UInt8] = []
    out.reserveCapacity(u.count / 2)
    var i = 0
    while i < u.count {
      guard let h = nib(u[i]), let l = nib(u[i + 1]) else { return nil }
      out.append(h << 4 | l)
      i += 2
    }
    return out
  }

  private static let b64: [UInt8] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)

  /// base64url without padding.
  public static func b64url(_ b: [UInt8]) -> String {
    var out: [UInt8] = []
    out.reserveCapacity((b.count + 2) / 3 * 4)
    var i = 0
    while i + 3 <= b.count {
      let n = UInt32(b[i]) << 16 | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2])
      out.append(b64[Int(n >> 18 & 63)]); out.append(b64[Int(n >> 12 & 63)])
      out.append(b64[Int(n >> 6 & 63)]); out.append(b64[Int(n & 63)])
      i += 3
    }
    let rest = b.count - i
    if rest == 1 {
      let n = UInt32(b[i]) << 16
      out.append(b64[Int(n >> 18 & 63)]); out.append(b64[Int(n >> 12 & 63)])
    } else if rest == 2 {
      let n = UInt32(b[i]) << 16 | UInt32(b[i + 1]) << 8
      out.append(b64[Int(n >> 18 & 63)]); out.append(b64[Int(n >> 12 & 63)]); out.append(b64[Int(n >> 6 & 63)])
    }
    return String(decoding: out, as: UTF8.self)
  }

  /// Decode base64url (padding tolerated, standard alphabet `+/` too); nil on garbage.
  public static func unb64url(_ s: String) -> [UInt8]? {
    var vals: [UInt8] = []
    for c in s.utf8 {
      switch c {
      case 0x41...0x5A: vals.append(c - 0x41)
      case 0x61...0x7A: vals.append(c - 0x61 + 26)
      case 0x30...0x39: vals.append(c - 0x30 + 52)
      case UInt8(ascii: "-"), UInt8(ascii: "+"): vals.append(62)
      case UInt8(ascii: "_"), UInt8(ascii: "/"): vals.append(63)
      case UInt8(ascii: "="): continue
      default: return nil
      }
    }
    if vals.count % 4 == 1 { return nil }
    var out: [UInt8] = []
    var i = 0
    while i + 4 <= vals.count {
      let n = UInt32(vals[i]) << 18 | UInt32(vals[i + 1]) << 12 | UInt32(vals[i + 2]) << 6 | UInt32(vals[i + 3])
      out.append(UInt8(n >> 16 & 0xFF)); out.append(UInt8(n >> 8 & 0xFF)); out.append(UInt8(n & 0xFF))
      i += 4
    }
    let rest = vals.count - i
    if rest == 2 {
      let n = UInt32(vals[i]) << 18 | UInt32(vals[i + 1]) << 12
      out.append(UInt8(n >> 16 & 0xFF))
    } else if rest == 3 {
      let n = UInt32(vals[i]) << 18 | UInt32(vals[i + 1]) << 12 | UInt32(vals[i + 2]) << 6
      out.append(UInt8(n >> 16 & 0xFF)); out.append(UInt8(n >> 8 & 0xFF))
    }
    return out
  }
}

#if !canImport(CryptoKit)
/// SHA-256 (FIPS 180-4) for platforms without CryptoKit. Not used on Apple devices.
enum SoftSHA256 {
  static let k: [UInt32] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]

  @inline(__always) static func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 - n)) }

  static func hash(_ input: [UInt8]) -> [UInt8] {
    var h: [UInt32] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    var msg = input
    let bitLen = UInt64(input.count) * 8
    msg.append(0x80)
    while msg.count % 64 != 56 { msg.append(0) }
    for s in stride(from: 56, through: 0, by: -8) { msg.append(UInt8(truncatingIfNeeded: bitLen >> UInt64(s))) }
    var w = [UInt32](repeating: 0, count: 64)
    var off = 0
    while off < msg.count {
      for t in 0..<16 {
        let j = off + t * 4
        w[t] = UInt32(msg[j]) << 24 | UInt32(msg[j + 1]) << 16 | UInt32(msg[j + 2]) << 8 | UInt32(msg[j + 3])
      }
      for t in 16..<64 {
        let s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        let s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w[t] = w[t - 16] &+ s0 &+ w[t - 7] &+ s1
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7]
      for t in 0..<64 {
        let S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        let ch = (e & f) ^ (~e & g)
        let t1 = hh &+ S1 &+ ch &+ k[t] &+ w[t]
        let S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        let maj = (a & b) ^ (a & c) ^ (b & c)
        let t2 = S0 &+ maj
        hh = g; g = f; f = e; e = d &+ t1; d = c; c = b; b = a; a = t1 &+ t2
      }
      h[0] = h[0] &+ a; h[1] = h[1] &+ b; h[2] = h[2] &+ c; h[3] = h[3] &+ d
      h[4] = h[4] &+ e; h[5] = h[5] &+ f; h[6] = h[6] &+ g; h[7] = h[7] &+ hh
      off += 64
    }
    var out: [UInt8] = []
    for v in h { out.append(contentsOf: [UInt8(v >> 24), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)]) }
    return out
  }
}
#endif
