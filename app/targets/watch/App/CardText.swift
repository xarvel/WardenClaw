// SPDX-License-Identifier: GPL-3.0-or-later
// Human words for the ids of protocol/DISPLAY.md (rules, flags, delegating groups) on the watch.
// The same meanings as the app (src/core/i18n) and wardenctl (card.go).

enum CardText {
  static func rule(_ id: String) -> String {
    switch id {
    case "rm-rf": return L.t("Recursive delete of /, home or a system directory")
    case "mkfs": return L.t("Creates a file system or wipes a disk")
    case "dd": return L.t("dd writes straight to a disk")
    case "curl-sh": return L.t("Downloads code and runs it at once")
    case "pipe-shell": return L.t("Pipes a stream into a shell: what runs is not visible")
    case "exec-dynamic": return L.t("Runs code that is assembled only at run time")
    case "decode": return L.t("Decodes hidden data (base64, hex)")
    case "netcat": return L.t("Raw network connection (nc, socat, /dev/tcp): data leak or remote access")
    case "reverse-shell": return L.t("Looks like a reverse shell: remote control of this host")
    case "chmod-root": return L.t("Recursive permission or owner change of system directories")
    case "shutdown": return L.t("Shutdown or reboot")
    case "gateway-stop": return L.t("Stops or restarts the OpenClaw gateway")
    case "openclaw-json": return L.t("Edits openclaw.json")
    case "openclaw-cli": return L.t("OpenClaw config, secrets, devices or update commands")
    case "openclaw-secrets": return L.t("OpenClaw secrets, credentials or database")
    case "secrets": return L.t("Mentions secrets, tokens or passwords")
    case "ssh": return L.t("SSH keys, /etc/shadow or sudoers")
    case "sudo": return L.t("Privilege escalation (sudo, doas, pkexec)")
    case "fork-bomb": return L.t("Fork bomb")
    case "firewall": return L.t("Resets or disables the firewall")
    case "crontab": return L.t("Removes the crontab")
    case "git-force": return L.t("git push that rewrites history")
    case "injection": return L.t("Text inside the command talks to the reviewer: looks like an injection")
    default: return id
    }
  }

  static func flag(_ f: String) -> String {
    switch f {
    case "control": return L.t("Control characters (shown as ⟨U+…⟩)")
    case "bidi": return L.t("Text direction controls: it reads differently from what runs")
    case "invisible": return L.t("Invisible characters or unusual spaces (shown as ⟨U+…⟩)")
    case "mixedScript": return L.t("Mixed alphabets in one word: letters may be spoofed")
    case "nonAsciiPath": return L.t("Non-ASCII characters in the program path (exe, argv[0]): a letter may be a look-alike")
    default: return f
    }
  }

  /// A flag of an environment entry (DISPLAY.md 7a): the sanitizer's, truncated, duplicate.
  static func envFlag(_ f: String) -> String {
    switch f {
    case "truncated": return L.t("the value is cut (longer than 1024 characters)")
    case "duplicate": return L.t("set more than once: the loader takes the last value, getenv the first")
    default: return flag(f)
    }
  }

  /// A loader variable in words: it pulls other code into the program before it starts.
  static func loader(_ names: [String]) -> String {
    L.t("Loader variables in the environment (\(names.joined(separator: ", "))): other code is loaded into the program")
  }

  static func delegating(_ id: String) -> String {
    switch id {
    case "session-detach": return L.t("detaches from the session: children leave supervision")
    case "service-managers": return L.t("runs through systemd or D-Bus, outside the wardend tree")
    case "containers": return L.t("runs in a container, outside the wardend tree")
    case "multiplexers": return L.t("runs in a terminal multiplexer, outside the tree")
    case "schedulers": return L.t("delayed run outside the tree")
    case "privilege-and-ns": return L.t("changes privileges or namespaces")
    case "remote": return L.t("runs on another host")
    default: return id
    }
  }

  // Alphabet groups of DISPLAY.md section 3 in words: "a Cyrillic “о” among Latin letters", "⟨Cyr.⟩".
  static func scriptAdj(_ s: String) -> String {
    switch s {
    case "latin": return L.t("a Latin")
    case "greek": return L.t("a Greek")
    case "cyrillic": return L.t("a Cyrillic")
    case "armenian": return L.t("an Armenian")
    case "cherokee": return L.t("a Cherokee")
    case "fullwidth": return L.t("a fullwidth")
    default: return s
    }
  }

  static func scriptAmong(_ s: String) -> String {
    switch s {
    case "latin": return L.t("Latin letters")
    case "greek": return L.t("Greek letters")
    case "cyrillic": return L.t("Cyrillic letters")
    case "armenian": return L.t("Armenian letters")
    case "cherokee": return L.t("Cherokee letters")
    case "fullwidth": return L.t("fullwidth letters")
    default: return s
    }
  }

  static func scriptShort(_ s: String) -> String {
    switch s {
    case "latin": return L.t("Lat.")
    case "greek": return L.t("Gr.")
    case "cyrillic": return L.t("Cyr.")
    case "armenian": return L.t("Arm.")
    case "cherokee": return L.t("Cher.")
    case "fullwidth": return L.t("FW")
    default: return s
    }
  }

  /// A long word in a reason: a window of 40 scalars around the first odd letter.
  static func clipWord(_ word: String, _ firstOdd: Int) -> String {
    let a = Array(word.unicodeScalars)
    guard a.count > 40 else { return word }
    let from = max(0, min(firstOdd - 15, a.count - 40))
    let to = min(a.count, from + 40)
    var v = String.UnicodeScalarView()
    v.append(contentsOf: a[from..<to])
    return (from > 0 ? "…" : "") + String(v) + (to < a.count ? "…" : "")
  }

  /// Where exactly a letter is spoofed, as the app and wardenctl say it: "In the word “Nоrthern” a
  /// Cyrillic “о” among Latin letters" (the same letter of a word once; three words, then a count).
  static func mixed(_ words: [Display.MixedWord]) -> [String] {
    var out: [String] = []
    for (i, w) in words.enumerated() {
      if i == 3 {
        out.append(L.t("More words with mixed alphabets: \(words.count - 3)"))
        break
      }
      var seen: [String] = []
      var letters: [String] = []
      for o in w.odd where !seen.contains(where: { sameCodeUnits($0, o.char) }) {
        seen.append(o.char)
        letters.append(L.t("\(scriptAdj(o.script)) “\(o.char)”"))
      }
      let word = clipWord(w.word, w.odd.first?.at ?? 0)
      let list = letters.joined(separator: ", ")
      out.append(L.t("In the word “\(word)” \(list) among \(scriptAmong(w.among))"))
    }
    return out
  }

  /// The verdict of the shared rules (DISPLAY.md 5.3) for the "Assessment, not signed" block, as the
  /// app words it: the blocklist first, then the injection detector; nil when no rule matched.
  static func ruleVerdict(_ v: Display.View) -> String? {
    if v.danger.contains(where: { $0 != "injection" }) { return L.t("blocklist matched") }
    if v.danger.contains("injection") { return L.t("looks like an injection") }
    return nil
  }

  /// Why a card is dangerous, from the signed envelope only (plus meta, which may only add).
  static func reasons(_ card: Card) -> [String] {
    var out = card.view.danger.map(rule)
    for f in card.view.flags {
      // mixed alphabets: which word and which letter, not just "in one word"
      if f == "mixedScript" && !card.view.mixed.isEmpty { out += mixed(card.view.mixed) } else { out.append(flag(f)) }
    }
    if let d = card.view.delegating {
      out.append(L.t("Delegating launch: ") + delegating(d))
    } else if card.cls == "delegating" {
      out.append(L.t("Delegating launch (says the server, not signed)"))
    }
    // the signed env (DISPLAY.md 7a): loader variables, then each flag of its entries once
    if !card.env.loader.isEmpty { out.append(loader(card.env.loader)) }
    for f in Display.envFlagOrder where card.env.entries.contains(where: { $0.flags.contains(f) }) {
      out.append(L.t("Environment: ") + envFlag(f))
    }
    return out
  }

  static func form(_ v: Display.View) -> String {
    switch v.form {
    case "wrapper": return L.t("Inside the claude-cli wrapper")
    case "shell": return (v.shell ?? "sh") + " -c"
    default: return "argv"
    }
  }
}
