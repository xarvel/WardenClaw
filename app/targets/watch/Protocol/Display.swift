// SPDX-License-Identifier: Apache-2.0
// Showing a card (protocol/DISPLAY.md): the same spec as app/src/core/display.ts (reference) and
// daemon/cmd/wardenctl/display.go, checked against protocol/vectors/display_vectors.json by
// WardenProtocolTests/DisplayTests.swift. Display only: the digest is computed over the envelope
// as it is.
//
// Everything works on Unicode scalars, not on Swift Characters: grapheme clustering and canonical
// equivalence would make the watch see a different string than the phone and wardenctl.

public enum Display {
  // MARK: code point classes (DISPLAY.md, section 2)

  public enum CpClass: String {
    case lf, tab, ctrlSpace, ctrl, bidi, oddSpace, invisible
  }

  public static let classes: [(UInt32, UInt32, CpClass)] = [
    (0x0000, 0x0008, .ctrl),
    (0x0009, 0x0009, .tab),
    (0x000A, 0x000A, .lf),
    (0x000B, 0x000D, .ctrlSpace),
    (0x000E, 0x001F, .ctrl),
    (0x007F, 0x0084, .ctrl),
    (0x0085, 0x0085, .ctrlSpace),
    (0x0086, 0x009F, .ctrl),
    (0x00A0, 0x00A0, .oddSpace),
    (0x00AD, 0x00AD, .invisible),
    (0x034F, 0x034F, .invisible),
    (0x0600, 0x0605, .invisible),
    (0x061C, 0x061C, .bidi),
    (0x06DD, 0x06DD, .invisible),
    (0x070F, 0x070F, .invisible),
    (0x0890, 0x0891, .invisible),
    (0x08E2, 0x08E2, .invisible),
    (0x115F, 0x1160, .invisible),
    (0x1680, 0x1680, .oddSpace),
    (0x17B4, 0x17B5, .invisible),
    (0x180B, 0x180F, .invisible),
    (0x2000, 0x200A, .oddSpace),
    (0x200B, 0x200D, .invisible),
    (0x200E, 0x200F, .bidi),
    (0x2028, 0x2029, .ctrlSpace),
    (0x202A, 0x202E, .bidi),
    (0x202F, 0x202F, .oddSpace),
    (0x205F, 0x205F, .oddSpace),
    (0x2060, 0x2064, .invisible),
    (0x2066, 0x2069, .bidi),
    (0x206A, 0x206F, .invisible),
    (0x2800, 0x2800, .invisible),
    (0x3000, 0x3000, .oddSpace),
    (0x3164, 0x3164, .invisible),
    (0xD800, 0xDFFF, .ctrl),
    (0xFEFF, 0xFEFF, .invisible),
    (0xFFA0, 0xFFA0, .invisible),
    (0xFFF9, 0xFFFB, .invisible),
    (0x110BD, 0x110BD, .invisible),
    (0x110CD, 0x110CD, .invisible),
    (0x13430, 0x1343F, .invisible),
    (0x1BCA0, 0x1BCA3, .invisible),
    (0x1D173, 0x1D17A, .invisible),
    (0xE0001, 0xE0001, .invisible),
    (0xE0020, 0xE007F, .invisible),
  ]

  public static func cpClass(_ c: UInt32) -> CpClass? {
    var lo = 0
    var hi = classes.count - 1
    while lo <= hi {
      let mid = (lo + hi) / 2
      let (a, b, k) = classes[mid]
      if c < a { hi = mid - 1 } else if c > b { lo = mid + 1 } else { return k }
    }
    return nil
  }

  public static let flagOrder = ["control", "bidi", "invisible", "mixedScript", "nonAsciiPath"]

  static func flagOf(_ k: CpClass) -> String? {
    switch k {
    case .ctrlSpace, .ctrl: return "control"
    case .bidi: return "bidi"
    case .oddSpace, .invisible: return "invisible"
    case .lf, .tab: return nil
    }
  }

  static func ordered(_ set: Set<String>) -> [String] { flagOrder.filter { set.contains($0) } }

  static func scalars(_ s: String) -> [Unicode.Scalar] { Array(s.unicodeScalars) }

  static func string(_ a: [Unicode.Scalar]) -> String {
    var v = String.UnicodeScalarView()
    v.append(contentsOf: a)
    return String(v)
  }

  static func hexUpper(_ c: UInt32) -> String {
    let digits = Array("0123456789ABCDEF".unicodeScalars)
    var out: [Unicode.Scalar] = []
    var x = c
    repeat {
      out.insert(digits[Int(x & 0xF)], at: 0)
      x >>= 4
    } while x > 0
    while out.count < 4 { out.insert("0", at: 0) }
    return string(out)
  }

  public static func marker(_ c: UInt32) -> String { "⟨U+" + hexUpper(c) + "⟩" }

  /// Sanitizer for display: invisible and control code points become ⟨U+XXXX⟩ and a flag.
  public static func sanitize(_ s: String) -> (text: String, flags: [String]) {
    var out = String.UnicodeScalarView()
    var flags = Set<String>()
    for c in s.unicodeScalars {
      guard let k = cpClass(c.value) else {
        out.append(c)
        continue
      }
      switch k {
      case .lf: out.append("⏎")
      case .tab: out.append("⇥")
      default:
        out.append(contentsOf: marker(c.value).unicodeScalars)
        if let f = flagOf(k) { flags.insert(f) }
      }
    }
    return (String(out), ordered(flags))
  }

  public static func sanitizeText(_ s: String) -> String { sanitize(s).text }

  /// Text for rules (DISPLAY.md, section 5.1).
  public static func normalizeForRules(_ s: String) -> String {
    var out = String.UnicodeScalarView()
    var prevSpace = false
    for c in s.unicodeScalars {
      let v = c.value
      let k = cpClass(v)
      var ch: Unicode.Scalar
      if k == .lf {
        ch = "\n"
      } else if k == .tab || k == .ctrlSpace || k == .oddSpace || v == 0x20 {
        ch = " "
      } else if k != nil {
        continue
      } else if v == 0x27 || v == 0x22 || v == 0x5C {
        continue
      } else if (0x41...0x5A).contains(v) || (0x410...0x42F).contains(v) {
        ch = Unicode.Scalar(v + 0x20)!
      } else if v == 0x401 {
        ch = "ё"
      } else {
        ch = c
      }
      if ch == " " {
        if prevSpace { continue }
        prevSpace = true
      } else {
        prevSpace = false
      }
      out.append(ch)
    }
    return String(out)
  }

  // MARK: rules (DISPLAY.md, section 5)

  public struct Rule: Equatable {
    public let id: String
    public let kind: String
    public let re: String
  }

  public static let rules: [Rule] = [
    Rule(id: "rm-rf", kind: "block", re: #"\brm\s+(-[a-z]*\s+)*(-[a-z]*r[a-z]*|--recursive)(\s+-[a-z-]*)*(\s+[^\s;&|]+)*?\s+(\/|~|\$\{?home\}?|\/home(\/[^\/\s]+)?|\/root|\/etc|\/usr|\/var|\/boot|\/bin|\/sbin|\/lib|\/lib64|\/opt|\/srv|\/mnt(\/[^\/\s]+)?|\/media)\/?\*?(\s|$)"#),
    Rule(id: "mkfs", kind: "block", re: #"\b(mkfs(\.[a-z0-9]+)?|mke2fs|mkswap|wipefs|sfdisk|cfdisk|sgdisk|blkdiscard)\b"#),
    Rule(id: "dd", kind: "block", re: #"\bdd\b[^|;&]*\bof=\/dev\/(sd|nvme|mmcblk|disk|vd|hd|xvd)"#),
    Rule(id: "curl-sh", kind: "block", re: #"\b(curl|wget)\b[^|]*\|&?\s*(sudo\s+)?(ba|z|da|k)?sh\b"#),
    Rule(id: "pipe-shell", kind: "block", re: #"\|&?\s*(sudo\s+)?(env\s+)?(\/[a-z\/]*\/)?(ba|z|da|k|fi|c|tc)?sh\b"#),
    Rule(id: "exec-dynamic", kind: "block", re: #"\beval\s+(\$|`)|\b(ba|z|da|k)?sh\s+-[a-z]*c\s+(\$|`)|(^|[\s;&|])(source|\.)\s+<\("#),
    Rule(id: "decode", kind: "block", re: #"\bbase64\s+([^\s;&|]+\s+)*?(-[a-z]*d[a-z]*|--decode)\b|\bxxd\s+([^\s;&|]+\s+)*?-[a-z]*r"#),
    Rule(id: "netcat", kind: "block", re: #"(^|[\s|;&(\/])(nc|ncat|netcat|socat|telnet)(\s|$)|\/dev\/(tcp|udp)\/"#),
    Rule(id: "reverse-shell", kind: "block", re: #"\bsocket\b.*\.connect\(|(\/|\b)(ba|z|da|k)?sh\W{1,3}-i\b|\bpty\.spawn\b"#),
    Rule(id: "chmod-root", kind: "block", re: #"\bch(mod|own|grp)\s+(-[a-z]*r[a-z]*|--recursive)[^;&|]*\s\/(bin|boot|etc|home|lib|usr|var)?\/?(\s|$)"#),
    Rule(id: "shutdown", kind: "block", re: #"\b(shutdown|reboot|poweroff|halt|init\s+[06])\b"#),
    Rule(id: "gateway-stop", kind: "block", re: #"\bsystemctl\s+(--user\s+)?(stop|restart|disable|mask|kill)\s+\S*openclaw"#),
    Rule(id: "openclaw-json", kind: "block", re: #"openclaw\.json\b"#),
    Rule(id: "openclaw-cli", kind: "block", re: #"\bopenclaw\s+(config\s+(set|unset|patch)|secrets|devices\s+(approve|clear|remove)|update)\b"#),
    Rule(id: "openclaw-secrets", kind: "block", re: #"\.openclaw\/(secrets|credentials|agents\/[^\/\s]+\/agent\/[^\s]*sqlite)"#),
    Rule(id: "secrets", kind: "block", re: #"\b(secret|token|password|passwd|api[_-]?key|private[_-]?key)s?\b"#),
    Rule(id: "ssh", kind: "block", re: #"\/etc\/(shadow|sudoers)\b|(~|\$\{?home\}?)\/\.ssh\b|\.ssh\/(id_|authorized_keys)"#),
    Rule(id: "sudo", kind: "block", re: #"\b(sudo|doas|pkexec)\b"#),
    Rule(id: "fork-bomb", kind: "block", re: #":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"#),
    Rule(id: "firewall", kind: "block", re: #"\b(iptables|ip6tables|nft|ufw)\b.*(\s(-f|--flush)\b|\b(flush|reset|disable)\b)"#),
    Rule(id: "crontab", kind: "block", re: #"\bcrontab\s+([^\s;&|]+\s+)*?-[a-z]*r[a-z]*\b"#),
    Rule(id: "git-force", kind: "block", re: #"\bgit\s+push\b[^;&|]*(--force|\s-[a-z]*f[a-z]*\b|\s\+\S)"#),
    Rule(id: "injection", kind: "injection", re: #"ignore\s+(all\s+|the\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)|you\s+are\s+(now\s+)?(an?\s+)?(ai|assistant|model|reviewer|approver|judge)\b|\bas\s+(the\s+|an?\s+)?(ai\s+)?(reviewer|approver|judge)\b|\bapprove\s+(this|it|the\s+command|immediately)\b|\ballow[- ](once|always)\b|\bdecision\s*[:=]\s*(allow|deny|ask)\b|\bthis\s+(command|request|action)\s+is\s+(safe|harmless|pre-?approved)|\bdo\s+not\s+(deny|block|flag)\b|\bplease\s+(approve|allow)\b|\bsystem\s+prompt\b|\bpre-?approved\b|\bnote\s+(to|for)\s+(the\s+)?(ai|reviewer|approver|judge|model)\b|\b(reviewer|approver)\s*(note\b|:)|одобри|разреши\s+(эту|команду|это)|ты\s+(ии|модель|ревьюер|судья)|игнорируй\s+(предыдущие|все|инструкции)"#),
  ]

  /// JS-like semantics: ASCII \w and \b, matching on scalars (DISPLAY.md, section 5.2).
  static func compile(_ re: String) -> Regex<AnyRegexOutput>? {
    guard let r = try? Regex(re) else { return nil }
    return r.asciiOnlyWordCharacters().wordBoundaryKind(.simple).matchingSemantics(.unicodeScalar)
  }

  static let compiled: [String: Regex<AnyRegexOutput>] = {
    var m: [String: Regex<AnyRegexOutput>] = [:]
    for r in rules {
      if let c = compile(r.re) { m[r.id] = c }
    }
    return m
  }()

  static let evalPart = compile(#"(^|[\s;&|(])eval(\s|$)"#)

  static func found(_ re: Regex<AnyRegexOutput>?, _ text: String) -> Bool {
    // a pattern that does not compile counts as a match: fail closed (the card becomes dangerous)
    guard let re = re else { return true }
    return (try? re.firstMatch(in: text)) != nil
  }

  /// Ids of the rules found in a normalized text, in table order.
  public static func matchRules(_ norm: String) -> [String] {
    rules.filter { found(compiled[$0.id], norm) }.map { $0.id }
  }

  static func orderRules(_ ids: Set<String>) -> [String] { rules.map { $0.id }.filter { ids.contains($0) } }

  // MARK: delegating launches (daemon/policy/defaults.json, delegating)

  public static let delegating: [(id: String, names: [String])] = [
    ("session-detach", ["setsid", "daemon", "start-stop-daemon", "disown"]),
    ("service-managers", ["systemd-run", "systemctl", "service", "busctl", "dbus-send", "gdbus", "loginctl", "machinectl"]),
    ("containers", ["docker", "podman", "nerdctl", "ctr", "kubectl", "lxc", "lxc-attach", "incus", "firejail", "bwrap", "flatpak-spawn", "distrobox", "toolbox"]),
    ("multiplexers", ["tmux", "screen", "zellij", "abduco", "dtach"]),
    ("schedulers", ["at", "batch", "crontab", "anacron"]),
    ("privilege-and-ns", ["sudo", "su", "doas", "pkexec", "runuser", "nsenter", "unshare", "chroot", "setpriv", "capsh"]),
    ("remote", ["ssh", "mosh", "rsh", "scp", "sftp"]),
  ]

  public static func basename(_ p: String) -> String {
    let s = scalars(p)
    guard let i = s.lastIndex(of: "/") else { return p }
    return string(Array(s[(i + 1)...]))
  }

  static func delegatingOf(_ argv: [String], _ exe: String) -> String? {
    let names = [basename(exe), argv.first.map(basename) ?? ""]
    for g in delegating where names.contains(where: { n in g.names.contains { sameCodeUnits($0, n) } }) {
      return g.id
    }
    return nil
  }

  // MARK: homoglyphs (DISPLAY.md, section 3)
  // Mixed alphabets inside one run of letters, and non-ASCII in the path of the program. A word
  // wholly in one alphabet (Russian file and folder names) raises nothing.

  /// Alphabet groups: 1 Latin, 2 Greek, 3 Cyrillic, 4 Armenian, 5 Cherokee, 6 fullwidth Latin.
  public static let scriptRanges: [(UInt32, UInt32, Int)] = [
    (0x0041, 0x005A, 1), (0x0061, 0x007A, 1), (0x00C0, 0x00D6, 1), (0x00D8, 0x00F6, 1), (0x00F8, 0x024F, 1),
    (0x0370, 0x03FF, 2),
    (0x0400, 0x052F, 3),
    (0x0531, 0x058F, 4),
    (0x13A0, 0x13FF, 5),
    (0x1C80, 0x1C8F, 3),
    (0x1E00, 0x1EFF, 1),
    (0x1F00, 0x1FFF, 2),
    (0x2DE0, 0x2DFF, 3),
    (0xA640, 0xA69F, 3),
    (0xAB70, 0xABBF, 5),
    (0xFF21, 0xFF3A, 6), (0xFF41, 0xFF5A, 6),
  ]

  static func scriptOf(_ c: UInt32) -> Int {
    for (a, b, s) in scriptRanges where c >= a && c <= b { return s }
    return 0
  }

  /// Combining marks: no alphabet of their own, they do not end a run of letters.
  public static let markRanges: [(UInt32, UInt32)] = [(0x0300, 0x036F), (0x1AB0, 0x1AFF), (0x1DC0, 0x1DFF), (0x20D0, 0x20FF), (0xFE20, 0xFE2F)]

  static func isMark(_ c: UInt32) -> Bool {
    for (a, b) in markRanges where c >= a && c <= b { return true }
    return false
  }

  /// Names of the groups 1...6 (vectors.scriptNames), as used in `among` and `odd[].script`.
  public static let scriptNames = ["latin", "greek", "cyrillic", "armenian", "cherokee", "fullwidth"]

  /// A letter of another alphabet than the run's main one; `at` is its index in `word` (scalars of
  /// the shown text).
  public struct OddLetter: Equatable {
    public let at: Int
    public let char: String
    public let script: String
  }

  /// A run of letters that mixes alphabets, as the person sees it: `at` is the index of its first
  /// scalar in the sanitized text, `word` the run in that text, `among` its main alphabet (the most
  /// letters; on a tie the one whose letter comes first), `odd` the letters of the other ones.
  public struct MixedRun: Equatable {
    public let at: Int
    public let word: String
    public let among: String
    public let odd: [OddLetter]
  }

  /// A mixed word of the card (no position: it may come from argv, exe or the chain).
  public struct MixedWord: Equatable {
    public let word: String
    public let among: String
    public let odd: [OddLetter]
  }

  /// How many scalars a scalar takes after the sanitizer (a ⟨U+XXXX⟩ marker or itself).
  static func shownLength(_ c: UInt32) -> Int {
    guard let k = cpClass(c), k != .lf, k != .tab else { return 1 }
    return marker(c).unicodeScalars.count
  }

  /// The mixed runs of a string (DISPLAY.md, section 3) with positions in its sanitized text: not
  /// only that alphabets are mixed, but which letter is the odd one.
  public static func mixedRuns(_ s: String) -> [MixedRun] {
    var out: [MixedRun] = []
    var pos = 0
    var runAt = -1
    var raw: [Unicode.Scalar] = []
    var letters: [(at: Int, g: Int, c: Unicode.Scalar)] = []
    func flush() {
      if runAt >= 0 {
        var count: [Int: Int] = [:]
        var order: [Int] = [] // groups in the order of their first letter
        for l in letters {
          if count[l.g] == nil { order.append(l.g) }
          count[l.g, default: 0] += 1
        }
        if order.count > 1 {
          var main = order[0]
          for g in order.dropFirst() where count[g, default: 0] > count[main, default: 0] { main = g }
          let odd = letters.filter { $0.g != main }.map { OddLetter(at: $0.at, char: String($0.c), script: scriptNames[$0.g - 1]) }
          out.append(MixedRun(at: runAt, word: sanitize(string(raw)).text, among: scriptNames[main - 1], odd: odd))
        }
      }
      runAt = -1
      raw = []
      letters = []
    }
    for c in s.unicodeScalars {
      let g = scriptOf(c.value)
      if g == 0 && !isMark(c.value) {
        flush()
      } else {
        if runAt < 0 { runAt = pos }
        if g != 0 { letters.append((pos - runAt, g, c)) }
        raw.append(c)
      }
      pos += shownLength(c.value)
    }
    flush()
    return out
  }

  /// The mixed words of several strings in order, without repeats (the same word in argv[0] and exe is one).
  static func mixedWords(_ strings: [String]) -> [MixedWord] {
    var out: [MixedWord] = []
    for s in strings {
      for r in mixedRuns(s) {
        let w = MixedWord(word: r.word, among: r.among, odd: r.odd)
        if !out.contains(where: { sameCodeUnits($0.word, w.word) && $0.among == w.among && $0.odd.count == w.odd.count && zip($0.odd, w.odd).allSatisfy { a, b in a.at == b.at && sameCodeUnits(a.char, b.char) && a.script == b.script } }) {
          out.append(w)
        }
      }
    }
    return out
  }

  /// A piece of shown text: plain, or an odd letter (with the combining marks after it).
  public struct MarkedSegment: Equatable {
    public let text: String
    public let odd: OddLetter?
  }

  /// A sanitized text in pieces for highlighting: the odd letters of the mixed runs as their own
  /// pieces. The positions of `runs` are scalars of this text (as mixedRuns returns them).
  public static func markOdd(_ text: String, _ runs: [MixedRun]) -> [MarkedSegment] {
    var odd: [Int: OddLetter] = [:]
    for r in runs { for o in r.odd { odd[r.at + o.at] = o } }
    if odd.isEmpty { return [MarkedSegment(text: text, odd: nil)] }
    let a = scalars(text)
    var out: [MarkedSegment] = []
    var from = 0
    var i = 0
    while i < a.count {
      guard let o = odd[i] else {
        i += 1
        continue
      }
      if i > from { out.append(MarkedSegment(text: string(Array(a[from..<i])), odd: nil)) }
      var j = i + 1
      while j < a.count && isMark(a[j].value) { j += 1 }
      out.append(MarkedSegment(text: string(Array(a[i..<j])), odd: o))
      from = j
      i = j
    }
    if from < a.count { out.append(MarkedSegment(text: string(Array(a[from...])), odd: nil)) }
    return out
  }

  /// `mixedScript` if a run of letters (letters of the groups and combining marks in a row) mixes
  /// alphabets. Digits, punctuation, `/`, `.`, `-`, `_` and spaces end a run: `media/Сериалы` is not
  /// mixed, `pаypal` with a Cyrillic `а` is.
  public static func tokenFlags(_ s: String) -> [String] {
    var first = 0
    for c in s.unicodeScalars {
      let sc = scriptOf(c.value)
      if sc == 0 {
        if !isMark(c.value) { first = 0 }
        continue
      }
      if first == 0 { first = sc } else if sc != first { return ["mixedScript"] }
    }
    return []
  }

  /// The path of a program (exe, argv[0], exes of the chain): sanitizer flags, any non-ASCII code
  /// point, mixed alphabets.
  static func programFlags(_ p: String) -> [String] {
    var f = Set(sanitize(p).flags)
    if p.unicodeScalars.contains(where: { $0.value > 0x7F }) { f.insert("nonAsciiPath") }
    f.formUnion(tokenFlags(p))
    return ordered(f)
  }

  // MARK: splitting a command (DISPLAY.md, section 4)

  public struct RawPart: Equatable {
    public let raw: String
    public let sep: String
  }

  static func isWS(_ c: Unicode.Scalar) -> Bool { c == " " || c == "\t" || c == "\n" || c == "\r" || c.value == 0x0B || c.value == 0x0C }

  static func endSingle(_ s: [Unicode.Scalar], _ i: Int) -> Int {
    var j = i + 1
    while j < s.count {
      if s[j] == "'" { return j }
      j += 1
    }
    return s.count - 1
  }

  static func endEscaped(_ s: [Unicode.Scalar], _ i: Int, _ q: Unicode.Scalar) -> Int {
    var j = i + 1
    while j < s.count {
      if s[j] == "\\" {
        j += 2
        continue
      }
      if s[j] == q { return j }
      j += 1
    }
    return s.count - 1
  }

  static func endParens(_ s: [Unicode.Scalar], _ i: Int) -> Int {
    var depth = 0
    var j = i
    while j < s.count {
      let c = s[j]
      if c == "\\" {
        j += 2
        continue
      }
      if c == "'" {
        j = endSingle(s, j)
      } else if c == "\"" || c == "`" {
        j = endEscaped(s, j, c)
      } else if c == "(" {
        depth += 1
      } else if c == ")" {
        depth -= 1
        if depth == 0 { return j }
      }
      j += 1
    }
    return s.count - 1
  }

  static func isWordStop(_ c: Unicode.Scalar) -> Bool { isWS(c) || ";&|<>()".unicodeScalars.contains(c) }

  static func heredocWord(_ s: [Unicode.Scalar], _ k: Int) -> ([Unicode.Scalar], Int) {
    var word: [Unicode.Scalar] = []
    var j = k
    while j < s.count && !isWordStop(s[j]) {
      let c = s[j]
      if c == "'" || c == "\"" {
        let e = c == "'" ? endSingle(s, j) : endEscaped(s, j, "\"")
        let closed = s[e] == c && e > j
        let end = closed ? e : e + 1
        if j + 1 < end { word.append(contentsOf: s[(j + 1)..<end]) }
        j = e + 1
      } else if c == "\\" && j + 1 < s.count {
        word.append(s[j + 1])
        j += 2
      } else {
        word.append(c)
        j += 1
      }
    }
    return (word, min(j, s.count))
  }

  public static func splitShell(_ script: String) -> [RawPart] {
    let s = scalars(script)
    let n = s.count
    var parts: [RawPart] = []
    var cur: [Unicode.Scalar] = []
    var heredocs: [(delim: [Unicode.Scalar], strip: Bool)] = []
    func emit(_ sep: String) {
      var a = 0
      var b = cur.count
      while a < b && isWS(cur[a]) { a += 1 }
      while b > a && isWS(cur[b - 1]) { b -= 1 }
      if a < b { parts.append(RawPart(raw: string(Array(cur[a..<b])), sep: sep)) }
      cur.removeAll()
    }
    func take(_ from: Int, _ to: Int) {
      var k = from
      while k <= to && k < n {
        cur.append(s[k])
        k += 1
      }
    }
    func at(_ k: Int) -> Unicode.Scalar? { k >= 0 && k < n ? s[k] : nil }
    var i = 0
    while i < n {
      let c = s[i]
      let next = at(i + 1)
      if c == "\\" {
        take(i, i + 1)
        i += 2
      } else if c == "'" {
        let e = endSingle(s, i)
        take(i, e)
        i = e + 1
      } else if c == "\"" || c == "`" {
        let e = endEscaped(s, i, c)
        take(i, e)
        i = e + 1
      } else if (c == "$" || c == "<" || c == ">") && next == "(" {
        let e = endParens(s, i + 1)
        take(i, e)
        i = e + 1
      } else if c == "#" && (cur.isEmpty || isWS(cur[cur.count - 1])) {
        var e = i
        while e < n && s[e] != "\n" { e += 1 }
        take(i, e - 1)
        i = e
      } else if c == "<" && next == "<" && at(i + 2) != "<" {
        var j = i + 2
        var strip = false
        if at(j) == "-" {
          strip = true
          j += 1
        }
        var k = j
        while k < n && (s[k] == " " || s[k] == "\t") { k += 1 }
        let (word, end) = heredocWord(s, k)
        if word.isEmpty {
          take(i, j - 1)
          i = j
          continue
        }
        heredocs.append((word, strip))
        take(i, end - 1)
        i = end
      } else if c == "\n" {
        if !heredocs.isEmpty {
          cur.append("\n")
          i += 1
          for h in heredocs {
            while i < n {
              var e = i
              while e < n && s[e] != "\n" { e += 1 }
              var line = Array(s[i..<e])
              if h.strip {
                var t = 0
                while t < line.count && line[t] == "\t" { t += 1 }
                line = Array(line[t...])
              }
              take(i, e)
              i = e + 1
              if line == h.delim { break }
            }
          }
          heredocs.removeAll()
          emit("\n")
          continue
        }
        emit("\n")
        i += 1
      } else if c == ";" {
        emit(";")
        i += 1
      } else if c == "&" {
        let prev = cur.last
        if prev == "<" || prev == ">" {
          cur.append(c)
          i += 1
        } else if next == "&" {
          emit("&&")
          i += 2
        } else if next == ">" {
          cur.append(contentsOf: ["&", ">"])
          i += 2
        } else {
          emit("&")
          i += 1
        }
      } else if c == "|" {
        if cur.last == ">" {
          cur.append(c)
          i += 1
        } else if next == "|" {
          emit("||")
          i += 2
        } else {
          emit("|")
          i += next == "&" ? 2 : 1
        }
      } else {
        cur.append(c)
        i += 1
      }
    }
    emit("")
    return parts
  }

  // MARK: the claude-cli wrapper (DISPLAY.md, section 6)

  static let wrapMid = scalars(" 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval ")
  static let wrapTail = scalars(" && pwd -P >| ")
  static let wrapStdin = scalars(" < /dev/null")
  static let wrapHead = scalars("source ")
  static let quoteJoin = scalars("\"'\"")

  static func has(_ s: [Unicode.Scalar], _ at: Int, _ p: [Unicode.Scalar]) -> Bool {
    at >= 0 && at + p.count <= s.count && Array(s[at..<(at + p.count)]) == p
  }

  static func isSafePathChar(_ c: Unicode.Scalar) -> Bool {
    (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || c == "." || c == "_" || c == "/" || c == "-"
  }

  static func safePath(_ p: [Unicode.Scalar]) -> Bool { p.count > 1 && p[0] == "/" && p.allSatisfy(isSafePathChar) }

  /// `^prefix` + one or more chars of `set` + `suffix$`
  static func matches(_ s: [Unicode.Scalar], prefix: String, set: (Unicode.Scalar) -> Bool, suffix: String) -> Bool {
    let p = scalars(prefix)
    let x = scalars(suffix)
    guard s.count > p.count + x.count, has(s, 0, p), has(s, s.count - x.count, x) else { return false }
    return s[p.count..<(s.count - x.count)].allSatisfy(set)
  }

  static func isSnapshotPath(_ p: [Unicode.Scalar]) -> Bool {
    guard safePath(p), let i = p.lastIndex(of: "/") else { return false }
    let dir = Array(p[..<i])
    let file = Array(p[(i + 1)...])
    guard basename(string(dir)) == "shell-snapshots", has(file, 0, scalars("snapshot-bash-")), has(file, file.count - 3, scalars(".sh")) else { return false }
    // snapshot-bash-<digits>-<[a-z0-9]+>.sh
    let mid = Array(file[14..<max(14, file.count - 3)])
    guard let dash = mid.firstIndex(of: "-"), dash > 0, dash < mid.count - 1 else { return false }
    return mid[..<dash].allSatisfy { $0 >= "0" && $0 <= "9" } && mid[(dash + 1)...].allSatisfy { ($0 >= "a" && $0 <= "z") || ($0 >= "0" && $0 <= "9") }
  }

  static func isCwdFile(_ p: [Unicode.Scalar]) -> Bool {
    guard safePath(p), let i = p.lastIndex(of: "/") else { return false }
    return matches(Array(p[(i + 1)...]), prefix: "claude-", set: { ($0 >= "0" && $0 <= "9") || ($0 >= "a" && $0 <= "f") }, suffix: "-cwd")
  }

  /// The command inside a claude-cli wrapper on the exact template, or nil.
  public static func claudeWrapper(_ argv: [String]) -> (command: String, snapshot: String, cwdFile: String)? {
    guard argv.count == 3, sameCodeUnits(basename(argv[0]), "bash"), sameCodeUnits(argv[1], "-c") else { return nil }
    let s = scalars(argv[2])
    guard has(s, 0, wrapHead), let sp = s[wrapHead.count...].firstIndex(of: " ") else { return nil }
    let snap = Array(s[wrapHead.count..<sp])
    guard isSnapshotPath(snap), has(s, sp, wrapMid) else { return nil }
    var i = sp + wrapMid.count
    var cmd: [Unicode.Scalar] = []
    var segs = 0
    while true {
      if i < s.count && s[i] == "'" {
        guard let e = s[(i + 1)...].firstIndex(of: "'") else { return nil }
        cmd.append(contentsOf: s[(i + 1)..<e])
        i = e + 1
        segs += 1
      } else if segs > 0 && has(s, i, quoteJoin) {
        cmd.append("'")
        i += 3
      } else {
        break
      }
    }
    guard segs > 0 else { return nil }
    if has(s, i, wrapStdin) { i += wrapStdin.count }
    guard has(s, i, wrapTail) else { return nil }
    let cwd = Array(s[(i + wrapTail.count)...])
    guard isCwdFile(cwd) else { return nil }
    return (string(cmd), string(snap), string(cwd))
  }

  // MARK: the card model (DISPLAY.md, section 7)

  public struct Part: Equatable {
    public var text: String
    public var sep: String
    public var danger: [String]
    public var flags: [String]
    /// Where in `text` a letter is spoofed (mixed runs, positions in scalars of `text`).
    public var mixed: [MixedRun]
  }

  public struct View: Equatable {
    public let form: String
    public let wrapper: String?
    public let shell: String?
    public let command: String
    public let parts: [Part]
    public let visible: [Int]
    public let hidden: Int
    public let headline: Int?
    public let danger: [String]
    public let flags: [String]
    /// The mixed words behind the card's `mixedScript` flag: from argv, exe and the chain.
    public let mixed: [MixedWord]
    public let delegating: String?
    public let dangerous: Bool

    /// One line: the headline part and "(+N)".
    public var headlineText: String {
      guard let h = headline else { return "" }
      return parts.count > 1 ? parts[h].text + "  (+\(parts.count - 1))" : parts[h].text
    }
  }

  static let shells: Set<String> = ["sh", "bash", "dash", "zsh", "ksh", "ash"]

  static func isShellCFlag(_ a: String) -> Bool {
    let s = scalars(a)
    guard s.count >= 2, s[0] == "-" else { return false }
    let body = s[1...]
    return body.contains("c") && body.allSatisfy { "eiluxc".unicodeScalars.contains($0) } && body.filter { $0 == "c" }.count == 1
  }

  static func isPlainArg(_ a: String) -> Bool {
    let s = scalars(a)
    return !s.isEmpty && s.allSatisfy { c in
      (c >= "a" && c <= "z") || (c >= "A" && c <= "Z") || (c >= "0" && c <= "9") || "_@%+=:,./-".unicodeScalars.contains(c)
    }
  }

  public static func shellQuote(_ argv: [String]) -> String {
    argv.map { a in
      isPlainArg(a) ? a : "'" + string(scalars(a).flatMap { $0 == "'" ? scalars("'\\''") : [$0] }) + "'"
    }.joined(separator: " ")
  }

  struct NormPart {
    let raw: String
    let sep: String
    let norm: String
  }

  static func partsOf(_ raws: [NormPart], _ cardDanger: [String]) -> ([Part], Bool) {
    var parts = raws.map { r -> Part in
      let sz = sanitize(r.raw)
      return Part(text: sz.text, sep: r.sep, danger: matchRules(r.norm), flags: ordered(Set(sz.flags).union(tokenFlags(r.raw))), mixed: mixedRuns(r.raw))
    }
    var pipes: [[Int]] = []
    var cur: [Int] = []
    for (i, r) in raws.enumerated() {
      cur.append(i)
      if r.sep != "|" {
        pipes.append(cur)
        cur = []
      }
    }
    if !cur.isEmpty { pipes.append(cur) }
    var showAll = false
    for id in cardDanger where !parts.contains(where: { $0.danger.contains(id) }) {
      var foundAny = false
      for pipe in pipes where pipe.count >= 2 {
        if found(compiled[id], pipe.map { raws[$0].norm }.joined(separator: " | ")) {
          foundAny = true
          for i in pipe { parts[i].danger = orderRules(Set(parts[i].danger).union([id])) }
        }
      }
      if !foundAny { showAll = true }
    }
    return (parts, showAll)
  }

  /// Parts of the chains (joined by `|`, `|&`, `&&`, `||`; `;`, `&` and a newline end a chain) that
  /// have a part with a rule or a flag: such a chain is shown whole, or `tar cz ~/.ssh | 1 more | nc …`
  /// would hide what stands between the risky parts.
  static func riskyChains(_ parts: [Part], _ risky: (Int) -> Bool) -> [Bool] {
    var out = Array(repeating: false, count: parts.count)
    var start = 0
    for i in parts.indices {
      if ["|", "&&", "||"].contains(parts[i].sep) && i < parts.count - 1 { continue }
      let hit = (start...i).contains(where: risky)
      for k in start...i { out[k] = hit }
      start = i + 1
    }
    return out
  }

  static func visibility(_ parts: [Part], _ norms: [String], _ showAll: Bool) -> ([Int], Int, Int?) {
    let n = parts.count
    func risky(_ i: Int) -> Bool { !parts[i].danger.isEmpty || !parts[i].flags.isEmpty }
    func hasEval(_ i: Int) -> Bool { found(evalPart, norms[i]) }
    let inRiskyChain = riskyChains(parts, risky)
    let all = Array(0..<n)
    let visible = showAll || n <= 4 ? all : all.filter { $0 < 2 || $0 == n - 1 || inRiskyChain[$0] || hasEval($0) }
    if n == 0 { return (visible, 0, nil) }
    let head = visible.first(where: risky) ?? visible.first(where: hasEval) ?? 0
    return (visible, n - visible.count, head)
  }

  /// The card of an exec envelope: argv, exe, cwd and the process chain (all signed fields).
  public static func commandView(argv: [String], exe: String, cwd: String, chain: [String]) -> View {
    let wrap = claudeWrapper(argv)
    var form: String
    var shell: String?
    var command: String
    var raws: [NormPart] = []
    var cardDanger: [String]
    if wrap != nil || (argv.count == 3 && shells.contains(basename(argv[0])) && isShellCFlag(argv[1])) {
      form = wrap != nil ? "wrapper" : "shell"
      shell = basename(argv[0])
      command = wrap?.command ?? argv[2]
      raws = splitShell(command).map { NormPart(raw: $0.raw, sep: $0.sep, norm: normalizeForRules($0.raw)) }
      cardDanger = matchRules(normalizeForRules(command))
    } else {
      form = "argv"
      command = shellQuote(argv)
      var texts = [argv.joined(separator: " ")]
      if !argv.isEmpty && !exe.isEmpty { texts.append(([basename(exe)] + argv.dropFirst()).joined(separator: " ")) }
      cardDanger = orderRules(Set(texts.flatMap { matchRules(normalizeForRules($0)) }))
      if !argv.isEmpty { raws = [NormPart(raw: command, sep: "", norm: normalizeForRules(texts[0]))] }
    }
    var (parts, showAll) = partsOf(raws, cardDanger)
    if form == "argv" && !parts.isEmpty {
      parts[0].danger = cardDanger
      parts[0].flags = ordered(Set(parts[0].flags).union(argv.flatMap(tokenFlags)).union(programFlags(argv[0])))
      showAll = false
    }
    let (visible, hidden, headline) = visibility(parts, raws.map { $0.norm }, showAll)
    var flags = Set<String>()
    for a in argv {
      flags.formUnion(sanitize(a).flags)
      flags.formUnion(tokenFlags(a))
    }
    if let a0 = argv.first { flags.formUnion(programFlags(a0)) }
    if !exe.isEmpty { flags.formUnion(programFlags(exe)) }
    flags.formUnion(sanitize(cwd).flags)
    for c in chain { flags.formUnion(programFlags(c)) }
    let flagList = ordered(flags)
    let deleg = delegatingOf(argv, exe)
    return View(form: form, wrapper: wrap != nil ? "claude-cli" : nil, shell: shell, command: command, parts: parts, visible: visible,
                hidden: hidden, headline: headline, danger: cardDanger, flags: flagList, mixed: mixedWords(argv + [exe] + chain),
                delegating: deleg, dangerous: !cardDanger.isEmpty || !flagList.isEmpty || deleg != nil)
  }

  // MARK: the environment (DISPLAY.md, section 7a)

  /// Loader variables: with a non-empty value the dynamic loader pulls other code into the program.
  public static let loaderNames = ["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"]

  /// Order of an env entry's flags: the sanitizer's, then truncated, then duplicate.
  public static let envFlagOrder = ["control", "bidi", "invisible", "truncated", "duplicate"]

  public struct EnvEntry: Equatable {
    /// Name and value through the sanitizer.
    public let name: String
    public let value: String
    /// Code points cut off the value by wardend (0: the value is whole).
    public let cut: Int64
    public let flags: [String]
    /// A loader variable (loaderNames) with a non-empty value.
    public let loader: Bool
  }

  public struct EnvView: Equatable {
    public let entries: [EnvEntry]
    /// The distinct names of loader entries, in order of first appearance.
    public let loader: [String]
    /// A loader entry or an entry with flags: the card is dangerous, as with commandView.dangerous.
    public let dangerous: Bool

    public static let empty = EnvView(entries: [], loader: [], dangerous: false)
  }

  /// The env block of a card (same as envView in app/src/core/display.ts). Names compare by code
  /// units (Swift == would take "é" and "e\u{301}" for one name).
  public static func envView(_ env: [WardenProtocol.EnvVar]) -> EnvView {
    var seen: [[UInt8]: Int] = [:]
    for e in env { seen[Array(e.name.utf8), default: 0] += 1 }
    var entries: [EnvEntry] = []
    var loader: [String] = []
    var dangerous = false
    for e in env {
      let n = sanitize(e.name)
      let v = sanitize(e.value)
      let cut = max(0, e.cut ?? 0)
      var flags = ordered(Set(n.flags).union(v.flags))
      if cut > 0 { flags.append("truncated") }
      if (seen[Array(e.name.utf8)] ?? 0) > 1 { flags.append("duplicate") }
      let isLoader = !e.value.isEmpty && loaderNames.contains { sameCodeUnits($0, e.name) }
      if isLoader && !loader.contains(where: { sameCodeUnits($0, e.name) }) { loader.append(e.name) }
      if isLoader || !flags.isEmpty { dangerous = true }
      entries.append(EnvEntry(name: n.text, value: v.text, cut: cut, flags: flags, loader: isLoader))
    }
    return EnvView(entries: entries, loader: loader, dangerous: dangerous)
  }
}
