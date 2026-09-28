// SPDX-License-Identifier: GPL-3.0-or-later
// "Card truth": how to show an exec to a human and the judge (protocol/DISPLAY.md). One
// specification in three implementations: here (TypeScript), daemon/cmd/wardenctl/display.go (Go)
// and app/targets/watch/Protocol/Display.swift (Swift); all three are checked by the shared
// vectors protocol/vectors/display_vectors.json. Only the DISPLAY changes: the digest and the
// signature are computed over the envelope as is.
//
// The module is pure (no RN or i18n): it is compiled by the core tests and the vector generator.

export type Flag = "control" | "bidi" | "invisible" | "mixedScript" | "nonAsciiPath";
export const FLAG_ORDER: Flag[] = ["control", "bidi", "invisible", "mixedScript", "nonAsciiPath"];

export type RuleKind = "block" | "injection";
export type Rule = { id: string; kind: RuleKind; re: string };

// ---------------------------------------------------------------------------
// Code point classes (DISPLAY.md, section 2). The ranges are sorted and do not overlap.
// ---------------------------------------------------------------------------
export type CpClass = "lf" | "tab" | "ctrlSpace" | "ctrl" | "bidi" | "oddSpace" | "invisible";

export const CP_CLASSES: [number, number, CpClass][] = [
  [0x0000, 0x0008, "ctrl"],
  [0x0009, 0x0009, "tab"],
  [0x000a, 0x000a, "lf"],
  [0x000b, 0x000d, "ctrlSpace"],
  [0x000e, 0x001f, "ctrl"],
  [0x007f, 0x0084, "ctrl"],
  [0x0085, 0x0085, "ctrlSpace"],
  [0x0086, 0x009f, "ctrl"],
  [0x00a0, 0x00a0, "oddSpace"],
  [0x00ad, 0x00ad, "invisible"],
  [0x034f, 0x034f, "invisible"],
  [0x0600, 0x0605, "invisible"],
  [0x061c, 0x061c, "bidi"],
  [0x06dd, 0x06dd, "invisible"],
  [0x070f, 0x070f, "invisible"],
  [0x0890, 0x0891, "invisible"],
  [0x08e2, 0x08e2, "invisible"],
  [0x115f, 0x1160, "invisible"],
  [0x1680, 0x1680, "oddSpace"],
  [0x17b4, 0x17b5, "invisible"],
  [0x180b, 0x180f, "invisible"],
  [0x2000, 0x200a, "oddSpace"],
  [0x200b, 0x200d, "invisible"],
  [0x200e, 0x200f, "bidi"],
  [0x2028, 0x2029, "ctrlSpace"],
  [0x202a, 0x202e, "bidi"],
  [0x202f, 0x202f, "oddSpace"],
  [0x205f, 0x205f, "oddSpace"],
  [0x2060, 0x2064, "invisible"],
  [0x2066, 0x2069, "bidi"],
  [0x206a, 0x206f, "invisible"],
  [0x2800, 0x2800, "invisible"],
  [0x3000, 0x3000, "oddSpace"],
  [0x3164, 0x3164, "invisible"],
  [0xd800, 0xdfff, "ctrl"], // lone surrogates (only in JS strings)
  [0xfeff, 0xfeff, "invisible"],
  [0xffa0, 0xffa0, "invisible"],
  [0xfff9, 0xfffb, "invisible"],
  [0x110bd, 0x110bd, "invisible"],
  [0x110cd, 0x110cd, "invisible"],
  [0x13430, 0x1343f, "invisible"],
  [0x1bca0, 0x1bca3, "invisible"],
  [0x1d173, 0x1d17a, "invisible"],
  [0xe0001, 0xe0001, "invisible"],
  [0xe0020, 0xe007f, "invisible"],
];

export function cpClass(c: number): CpClass | null {
  let lo = 0;
  let hi = CP_CLASSES.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [a, b, k] = CP_CLASSES[mid];
    if (c < a) hi = mid - 1;
    else if (c > b) lo = mid + 1;
    else return k;
  }
  return null;
}

const FLAG_OF: Partial<Record<CpClass, Flag>> = { ctrlSpace: "control", ctrl: "control", bidi: "bidi", oddSpace: "invisible", invisible: "invisible" };

/** The code points of a string (in JS a lone surrogate stays a separate element). */
function toCodePoints(s: string): number[] {
  const out: number[] = [];
  for (const ch of s) out.push(ch.codePointAt(0) as number);
  return out;
}
function fromCodePoints(a: number[]): string {
  let s = "";
  for (let i = 0; i < a.length; i += 4096) s += String.fromCodePoint(...a.slice(i, i + 4096));
  return s;
}

export function marker(c: number): string {
  return `⟨U+${c.toString(16).toUpperCase().padStart(4, "0")}⟩`;
}

function sortFlags(set: Set<Flag>): Flag[] {
  return FLAG_ORDER.filter((f) => set.has(f));
}

/** Sanitizer for display: invisible and control characters become a ⟨U+XXXX⟩ marker and a flag. */
export function sanitize(s: string): { text: string; flags: Flag[] } {
  const flags = new Set<Flag>();
  let out = "";
  for (const c of toCodePoints(s)) {
    const k = cpClass(c);
    if (k === null) out += String.fromCodePoint(c);
    else if (k === "lf") out += "⏎";
    else if (k === "tab") out += "⇥";
    else {
      out += marker(c);
      flags.add(FLAG_OF[k] as Flag);
    }
  }
  return { text: out, flags: sortFlags(flags) };
}

export const sanitizeText = (s: string) => sanitize(s).text;

/**
 * Text for the rules: invisible characters removed, whitespace turned into a space, quotes and
 * backslashes removed, Latin and Cyrillic in lowercase, runs of spaces collapsed. The rules are
 * written for it.
 */
export function normalizeForRules(s: string): string {
  let out = "";
  let prevSpace = false;
  for (const c of toCodePoints(s)) {
    const k = cpClass(c);
    let ch: string | null;
    if (k === "lf") ch = "\n";
    else if (k === "tab" || k === "ctrlSpace" || k === "oddSpace" || c === 0x20) ch = " ";
    else if (k !== null) ch = null;
    else if (c === 0x27 || c === 0x22 || c === 0x5c) ch = null;
    else if (c >= 0x41 && c <= 0x5a) ch = String.fromCharCode(c + 0x20);
    else if (c >= 0x410 && c <= 0x42f) ch = String.fromCharCode(c + 0x20);
    else if (c === 0x401) ch = "ё";
    else ch = String.fromCodePoint(c);
    if (ch === null) continue;
    if (ch === " ") {
      if (prevSpace) continue;
      prevSpace = true;
    } else prevSpace = false;
    out += ch;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Rules: blocklist and injection detector (DISPLAY.md, section 5). Patterns are in lowercase and
// are applied to normalizeForRules(); a syntax subset that is the same for JS, RE2 and Swift Regex.
// ---------------------------------------------------------------------------
export const RULES: Rule[] = [
  {
    id: "rm-rf",
    kind: "block",
    re: "\\brm\\s+(-[a-z]*\\s+)*(-[a-z]*r[a-z]*|--recursive)(\\s+-[a-z-]*)*(\\s+[^\\s;&|]+)*?\\s+(\\/|~|\\$\\{?home\\}?|\\/home(\\/[^\\/\\s]+)?|\\/root|\\/etc|\\/usr|\\/var|\\/boot|\\/bin|\\/sbin|\\/lib|\\/lib64|\\/opt|\\/srv|\\/mnt(\\/[^\\/\\s]+)?|\\/media)\\/?\\*?(\\s|$)",
  },
  { id: "mkfs", kind: "block", re: "\\b(mkfs(\\.[a-z0-9]+)?|mke2fs|mkswap|wipefs|sfdisk|cfdisk|sgdisk|blkdiscard)\\b" },
  { id: "dd", kind: "block", re: "\\bdd\\b[^|;&]*\\bof=\\/dev\\/(sd|nvme|mmcblk|disk|vd|hd|xvd)" },
  { id: "curl-sh", kind: "block", re: "\\b(curl|wget)\\b[^|]*\\|&?\\s*(sudo\\s+)?(ba|z|da|k)?sh\\b" },
  { id: "pipe-shell", kind: "block", re: "\\|&?\\s*(sudo\\s+)?(env\\s+)?(\\/[a-z\\/]*\\/)?(ba|z|da|k|fi|c|tc)?sh\\b" },
  { id: "exec-dynamic", kind: "block", re: "\\beval\\s+(\\$|`)|\\b(ba|z|da|k)?sh\\s+-[a-z]*c\\s+(\\$|`)|(^|[\\s;&|])(source|\\.)\\s+<\\(" },
  { id: "decode", kind: "block", re: "\\bbase64\\s+([^\\s;&|]+\\s+)*?(-[a-z]*d[a-z]*|--decode)\\b|\\bxxd\\s+([^\\s;&|]+\\s+)*?-[a-z]*r" },
  { id: "netcat", kind: "block", re: "(^|[\\s|;&(\\/])(nc|ncat|netcat|socat|telnet)(\\s|$)|\\/dev\\/(tcp|udp)\\/" },
  { id: "reverse-shell", kind: "block", re: "\\bsocket\\b.*\\.connect\\(|(\\/|\\b)(ba|z|da|k)?sh\\W{1,3}-i\\b|\\bpty\\.spawn\\b" },
  { id: "chmod-root", kind: "block", re: "\\bch(mod|own|grp)\\s+(-[a-z]*r[a-z]*|--recursive)[^;&|]*\\s\\/(bin|boot|etc|home|lib|usr|var)?\\/?(\\s|$)" },
  { id: "shutdown", kind: "block", re: "\\b(shutdown|reboot|poweroff|halt|init\\s+[06])\\b" },
  { id: "gateway-stop", kind: "block", re: "\\bsystemctl\\s+(--user\\s+)?(stop|restart|disable|mask|kill)\\s+\\S*openclaw" },
  { id: "openclaw-json", kind: "block", re: "openclaw\\.json\\b" },
  { id: "openclaw-cli", kind: "block", re: "\\bopenclaw\\s+(config\\s+(set|unset|patch)|secrets|devices\\s+(approve|clear|remove)|update)\\b" },
  { id: "openclaw-secrets", kind: "block", re: "\\.openclaw\\/(secrets|credentials|agents\\/[^\\/\\s]+\\/agent\\/[^\\s]*sqlite)" },
  { id: "secrets", kind: "block", re: "\\b(secret|token|password|passwd|api[_-]?key|private[_-]?key)s?\\b" },
  { id: "ssh", kind: "block", re: "\\/etc\\/(shadow|sudoers)\\b|(~|\\$\\{?home\\}?)\\/\\.ssh\\b|\\.ssh\\/(id_|authorized_keys)" },
  { id: "sudo", kind: "block", re: "\\b(sudo|doas|pkexec)\\b" },
  { id: "fork-bomb", kind: "block", re: ":\\(\\)\\s*\\{\\s*:\\s*\\|\\s*:\\s*&\\s*\\}\\s*;\\s*:" },
  { id: "firewall", kind: "block", re: "\\b(iptables|ip6tables|nft|ufw)\\b.*(\\s(-f|--flush)\\b|\\b(flush|reset|disable)\\b)" },
  { id: "crontab", kind: "block", re: "\\bcrontab\\s+([^\\s;&|]+\\s+)*?-[a-z]*r[a-z]*\\b" },
  { id: "git-force", kind: "block", re: "\\bgit\\s+push\\b[^;&|]*(--force|\\s-[a-z]*f[a-z]*\\b|\\s\\+\\S)" },
  {
    id: "injection",
    kind: "injection",
    re: "ignore\\s+(all\\s+|the\\s+|any\\s+)?(previous|prior|above|earlier)\\s+(instructions|rules|prompts?)|you\\s+are\\s+(now\\s+)?(an?\\s+)?(ai|assistant|model|reviewer|approver|judge)\\b|\\bas\\s+(the\\s+|an?\\s+)?(ai\\s+)?(reviewer|approver|judge)\\b|\\bapprove\\s+(this|it|the\\s+command|immediately)\\b|\\ballow[- ](once|always)\\b|\\bdecision\\s*[:=]\\s*(allow|deny|ask)\\b|\\bthis\\s+(command|request|action)\\s+is\\s+(safe|harmless|pre-?approved)|\\bdo\\s+not\\s+(deny|block|flag)\\b|\\bplease\\s+(approve|allow)\\b|\\bsystem\\s+prompt\\b|\\bpre-?approved\\b|\\bnote\\s+(to|for)\\s+(the\\s+)?(ai|reviewer|approver|judge|model)\\b|\\b(reviewer|approver)\\s*(note\\b|:)|одобри|разреши\\s+(эту|команду|это)|ты\\s+(ии|модель|ревьюер|судья)|игнорируй\\s+(предыдущие|все|инструкции)",
  },
];

const compiled = new Map<string, RegExp>();
function ruleRe(r: Rule): RegExp {
  let re = compiled.get(r.id);
  if (!re) {
    re = new RegExp(r.re);
    compiled.set(r.id, re);
  }
  return re;
}

/** ids of the rules that matched the text (already normalized), in table order. */
export function matchRules(normalized: string): string[] {
  return RULES.filter((r) => ruleRe(r).test(normalized)).map((r) => r.id);
}

export function ruleKind(id: string): RuleKind | null {
  return RULES.find((r) => r.id === id)?.kind ?? null;
}

// ---------------------------------------------------------------------------
// Delegating launches: the same groups as delegating in daemon/policy/defaults.json.
// ---------------------------------------------------------------------------
export const DELEGATING: { id: string; names: string[] }[] = [
  { id: "session-detach", names: ["setsid", "daemon", "start-stop-daemon", "disown"] },
  { id: "service-managers", names: ["systemd-run", "systemctl", "service", "busctl", "dbus-send", "gdbus", "loginctl", "machinectl"] },
  { id: "containers", names: ["docker", "podman", "nerdctl", "ctr", "kubectl", "lxc", "lxc-attach", "incus", "firejail", "bwrap", "flatpak-spawn", "distrobox", "toolbox"] },
  { id: "multiplexers", names: ["tmux", "screen", "zellij", "abduco", "dtach"] },
  { id: "schedulers", names: ["at", "batch", "crontab", "anacron"] },
  { id: "privilege-and-ns", names: ["sudo", "su", "doas", "pkexec", "runuser", "nsenter", "unshare", "chroot", "setpriv", "capsh"] },
  { id: "remote", names: ["ssh", "mosh", "rsh", "scp", "sftp"] },
];

export function basename(p: string): string {
  const i = p.lastIndexOf("/");
  return i >= 0 ? p.slice(i + 1) : p;
}

function delegatingOf(argv: string[], exe: string): string | null {
  const names = [basename(exe), argv.length ? basename(argv[0]) : ""];
  for (const g of DELEGATING) if (names.some((n) => g.names.includes(n))) return g.id;
  return null;
}

// ---------------------------------------------------------------------------
// Homoglyphs (DISPLAY.md, section 3): mixed alphabets inside one run of letters and non-ASCII in
// the program path. A word entirely in one alphabet (Russian file and folder names) gives no flags.
// ---------------------------------------------------------------------------
/** Alphabet groups: [from, to, group]; 1 Latin, 2 Greek, 3 Cyrillic, 4 Armenian, 5 Cherokee, 6 fullwidth Latin. */
export const SCRIPTS: [number, number, number][] = [
  [0x0041, 0x005a, 1], [0x0061, 0x007a, 1], [0x00c0, 0x00d6, 1], [0x00d8, 0x00f6, 1], [0x00f8, 0x024f, 1],
  [0x0370, 0x03ff, 2],
  [0x0400, 0x052f, 3],
  [0x0531, 0x058f, 4],
  [0x13a0, 0x13ff, 5],
  [0x1c80, 0x1c8f, 3],
  [0x1e00, 0x1eff, 1],
  [0x1f00, 0x1fff, 2],
  [0x2de0, 0x2dff, 3],
  [0xa640, 0xa69f, 3],
  [0xab70, 0xabbf, 5],
  [0xff21, 0xff3a, 6], [0xff41, 0xff5a, 6],
];

export function scriptOf(c: number): number {
  for (const [a, b, s] of SCRIPTS) if (c >= a && c <= b) return s;
  return 0;
}

/** Combining marks: no alphabet of their own, do not break a run of letters (else a mark could split `pаypal`). */
export const MARKS: [number, number][] = [
  [0x0300, 0x036f],
  [0x1ab0, 0x1aff],
  [0x1dc0, 0x1dff],
  [0x20d0, 0x20ff],
  [0xfe20, 0xfe2f],
];

export function isMark(c: number): boolean {
  for (const [a, b] of MARKS) if (c >= a && c <= b) return true;
  return false;
}

/** Names of groups 1..6 (vectors.scriptNames): a group's name in `among` and `odd[].script`. */
export const SCRIPT_NAMES = ["latin", "greek", "cyrillic", "armenian", "cherokee", "fullwidth"] as const;
export type ScriptName = (typeof SCRIPT_NAMES)[number];

/** A letter not of the run's main alphabet: `at` is the index in `word` (code points of the shown text). */
export type OddLetter = { at: number; char: string; script: ScriptName };
/**
 * A mixed run of letters as a human sees it: `at` is the index of the run's first code point in the
 * sanitized text, `word` is the run in that text, `among` is the run's main alphabet (the most
 * letters; on a tie, the one whose letter came first), `odd` are the letters of other alphabets.
 */
export type MixedRun = { at: number; word: string; among: ScriptName; odd: OddLetter[] };
/** A mixed word of the card (no position: the word could come from argv, exe or the chain). */
export type MixedWord = { word: string; among: ScriptName; odd: OddLetter[] };

/** How many code points a code point takes after the sanitizer (a ⟨U+XXXX⟩ marker or itself). */
function shownLen(c: number): number {
  const k = cpClass(c);
  return k === null || k === "lf" || k === "tab" ? 1 : toCodePoints(marker(c)).length;
}

/**
 * The mixed runs of a string (DISPLAY.md, section 3) with positions in its sanitized text: a run
 * is group letters and combining marks in a row; everything else (digits, punctuation, `/`, `.`,
 * `-`, `_`, spaces) ends it, so `media/Сериалы` is not mixed, while `Nоrthern` with a Cyrillic "о"
 * is mixed, and one can see exactly which letter is foreign.
 */
export function mixedRuns(s: string): MixedRun[] {
  const out: MixedRun[] = [];
  let pos = 0;
  let runAt = -1;
  let raw: number[] = [];
  let letters: { at: number; g: number; c: number }[] = [];
  const flush = () => {
    if (runAt >= 0) {
      const count = new Map<number, number>(); // key order: the order of each group's first letter
      for (const l of letters) count.set(l.g, (count.get(l.g) ?? 0) + 1);
      if (count.size > 1) {
        let main = -1;
        for (const [g, n] of count) if (main < 0 || n > (count.get(main) as number)) main = g;
        const odd = letters.filter((l) => l.g !== main).map((l) => ({ at: l.at, char: String.fromCodePoint(l.c), script: SCRIPT_NAMES[l.g - 1] }));
        out.push({ at: runAt, word: sanitize(fromCodePoints(raw)).text, among: SCRIPT_NAMES[main - 1], odd });
      }
    }
    runAt = -1;
    raw = [];
    letters = [];
  };
  for (const c of toCodePoints(s)) {
    const g = scriptOf(c);
    if (g === 0 && !isMark(c)) flush();
    else {
      if (runAt < 0) runAt = pos;
      if (g !== 0) letters.push({ at: pos - runAt, g, c });
      raw.push(c);
    }
    pos += shownLen(c);
  }
  flush();
  return out;
}

/**
 * Homoglyph flag of a string: a run of letters (group letters and combining marks in a row) mixes
 * alphabets. Everything else (digits, punctuation, `/`, `.`, `-`, `_`, spaces) ends the run, so
 * `media/Сериалы` and `Северный маяк (2019) - Directors Cut.mkv` are not mixed, while `pаypal` and
 * `/usr/bin/pуthon` with a Cyrillic letter are mixed.
 */
export function tokenFlags(s: string): Flag[] {
  let first = 0;
  for (const c of toCodePoints(s)) {
    const sc = scriptOf(c);
    if (sc === 0) {
      if (!isMark(c)) first = 0;
      continue;
    }
    if (first === 0) first = sc;
    else if (sc !== first) return ["mixedScript"];
  }
  return [];
}

/** Mixed words of several strings in order, no repeats (the same word in argv[0] and exe counts once). */
function mixedWords(strings: string[]): MixedWord[] {
  const seen = new Set<string>();
  const out: MixedWord[] = [];
  for (const s of strings)
    for (const r of mixedRuns(s)) {
      const w: MixedWord = { word: r.word, among: r.among, odd: r.odd };
      const key = JSON.stringify(w);
      if (!seen.has(key)) {
        seen.add(key);
        out.push(w);
      }
    }
  return out;
}

/** A piece of the shown text: plain, or a foreign letter (with the combining marks after it). */
export type MarkedSegment = { text: string; odd: OddLetter | null };

/**
 * The text of a part (or other sanitized text) in pieces for highlighting: foreign letters of mixed
 * runs as separate pieces. The `runs` positions are code points of this text (as mixedRuns returns
 * them).
 */
export function markOdd(text: string, runs: MixedRun[] | undefined): MarkedSegment[] {
  const a = toCodePoints(text);
  const odd = new Map<number, OddLetter>();
  for (const r of runs ?? []) for (const o of r.odd) odd.set(r.at + o.at, o);
  if (!odd.size) return [{ text, odd: null }];
  const out: MarkedSegment[] = [];
  let from = 0;
  let i = 0;
  while (i < a.length) {
    const o = odd.get(i);
    if (!o) {
      i++;
      continue;
    }
    if (i > from) out.push({ text: fromCodePoints(a.slice(from, i)), odd: null });
    let j = i + 1;
    while (j < a.length && isMark(a[j])) j++;
    out.push({ text: fromCodePoints(a.slice(i, j)), odd: o });
    from = i = j;
  }
  if (from < a.length) out.push({ text: fromCodePoints(a.slice(from)), odd: null });
  return out;
}

/** The program path (exe, argv[0], chain exe): sanitizer, any non-ASCII character, mixed alphabets. */
function programFlags(p: string): Flag[] {
  const flags = new Set<Flag>(sanitize(p).flags);
  if (toCodePoints(p).some((x) => x > 0x7f)) flags.add("nonAsciiPath");
  for (const f of tokenFlags(p)) flags.add(f);
  return sortFlags(flags);
}

// ---------------------------------------------------------------------------
// Lexer: shell command → parts split on ; && || | & and newlines (DISPLAY.md, section 4).
// Executes and expands nothing, only splits, taking into account quotes, $(…), `…`, comments
// and heredoc.
// ---------------------------------------------------------------------------
export type Sep = ";" | "&&" | "||" | "|" | "&" | "\n" | "";
export type RawPart = { raw: string; sep: Sep };

const WS = new Set([0x20, 0x09, 0x0a, 0x0d, 0x0b, 0x0c]);
const C = (ch: string) => ch.codePointAt(0) as number;
const BS = C("\\"), SQ = C("'"), DQ = C('"'), BT = C("`"), DOLLAR = C("$"), LP = C("("), RP = C(")"), HASH = C("#"), LT = C("<"), GT = C(">"), AMP = C("&"), PIPE = C("|"), SEMI = C(";"), NL = 0x0a, DASH = C("-"), TABC = 0x09;

function trimWs(a: number[]): number[] {
  let i = 0;
  let j = a.length;
  while (i < j && WS.has(a[i])) i++;
  while (j > i && WS.has(a[j - 1])) j--;
  return a.slice(i, j);
}

/** End of single quotes opened at i: the index of the closing one or n-1. */
function endSingle(s: number[], i: number): number {
  for (let j = i + 1; j < s.length; j++) if (s[j] === SQ) return j;
  return s.length - 1;
}
/** End of "…" or `…` with backslash escapes inside. */
function endEscaped(s: number[], i: number, q: number): number {
  let j = i + 1;
  while (j < s.length) {
    if (s[j] === BS) {
      j += 2;
      continue;
    }
    if (s[j] === q) return j;
    j++;
  }
  return s.length - 1;
}
/** End of $( … ) / <( … ) / >( … ): i points at "(". */
function endParens(s: number[], i: number): number {
  let depth = 0;
  let j = i;
  while (j < s.length) {
    const c = s[j];
    if (c === BS) {
      j += 2;
      continue;
    }
    if (c === SQ) j = endSingle(s, j);
    else if (c === DQ || c === BT) j = endEscaped(s, j, c);
    else if (c === LP) depth++;
    else if (c === RP) {
      depth--;
      if (depth === 0) return j;
    }
    j++;
  }
  return s.length - 1;
}

const WORD_STOP = new Set([...WS, SEMI, AMP, PIPE, LT, GT, LP, RP]);

/** The heredoc delimiter word (quotes removed) and the index right after it. */
function heredocWord(s: number[], k: number): { word: number[]; end: number } {
  const word: number[] = [];
  let j = k;
  while (j < s.length && !WORD_STOP.has(s[j])) {
    const c = s[j];
    if (c === SQ || c === DQ) {
      const e = c === SQ ? endSingle(s, j) : endEscaped(s, j, DQ);
      const closed = s[e] === c && e > j;
      word.push(...s.slice(j + 1, closed ? e : e + 1));
      j = e + 1;
    } else if (c === BS && j + 1 < s.length) {
      word.push(s[j + 1]);
      j += 2;
    } else {
      word.push(c);
      j++;
    }
  }
  return { word, end: Math.min(j, s.length) };
}

function eqArr(a: number[], b: number[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

export function splitShell(script: string): RawPart[] {
  const s = toCodePoints(script);
  const n = s.length;
  const parts: RawPart[] = [];
  let cur: number[] = [];
  let heredocs: { delim: number[]; strip: boolean }[] = [];
  const emit = (sep: Sep) => {
    const t = trimWs(cur);
    if (t.length) parts.push({ raw: fromCodePoints(t), sep });
    cur = [];
  };
  const take = (from: number, to: number) => {
    for (let k = from; k <= to && k < n; k++) cur.push(s[k]);
  };
  let i = 0;
  while (i < n) {
    const c = s[i];
    const next = i + 1 < n ? s[i + 1] : -1;
    if (c === BS) {
      take(i, i + 1);
      i += 2;
      continue;
    }
    if (c === SQ) {
      const e = endSingle(s, i);
      take(i, e);
      i = e + 1;
      continue;
    }
    if (c === DQ || c === BT) {
      const e = endEscaped(s, i, c);
      take(i, e);
      i = e + 1;
      continue;
    }
    if ((c === DOLLAR || c === LT || c === GT) && next === LP) {
      const e = endParens(s, i + 1);
      take(i, e);
      i = e + 1;
      continue;
    }
    if (c === HASH && (cur.length === 0 || WS.has(cur[cur.length - 1]))) {
      let e = i;
      while (e < n && s[e] !== NL) e++;
      take(i, e - 1);
      i = e;
      continue;
    }
    if (c === LT && next === LT && !(i + 2 < n && s[i + 2] === LT)) {
      let j = i + 2;
      let strip = false;
      if (j < n && s[j] === DASH) {
        strip = true;
        j++;
      }
      let k = j;
      while (k < n && (s[k] === 0x20 || s[k] === TABC)) k++;
      const { word, end } = heredocWord(s, k);
      if (!word.length) {
        take(i, j - 1);
        i = j;
        continue;
      }
      heredocs.push({ delim: word, strip });
      take(i, end - 1);
      i = end;
      continue;
    }
    if (c === NL) {
      if (heredocs.length) {
        cur.push(NL);
        i++;
        for (const h of heredocs) {
          while (i < n) {
            let e = i;
            while (e < n && s[e] !== NL) e++;
            let line = s.slice(i, e);
            if (h.strip) {
              let t = 0;
              while (t < line.length && line[t] === TABC) t++;
              line = line.slice(t);
            }
            take(i, e);
            i = e + 1;
            if (eqArr(line, h.delim)) break;
          }
        }
        heredocs = [];
        emit("\n");
        continue;
      }
      emit("\n");
      i++;
      continue;
    }
    if (c === SEMI) {
      emit(";");
      i++;
      continue;
    }
    if (c === AMP) {
      const prev = cur.length ? cur[cur.length - 1] : -1;
      if (prev === LT || prev === GT) {
        cur.push(c);
        i++;
        continue;
      }
      if (next === AMP) {
        emit("&&");
        i += 2;
        continue;
      }
      if (next === GT) {
        cur.push(AMP, GT);
        i += 2;
        continue;
      }
      emit("&");
      i++;
      continue;
    }
    if (c === PIPE) {
      const prev = cur.length ? cur[cur.length - 1] : -1;
      if (prev === GT) {
        cur.push(c);
        i++;
        continue;
      }
      if (next === PIPE) {
        emit("||");
        i += 2;
        continue;
      }
      emit("|");
      i += next === AMP ? 2 : 1;
      continue;
    }
    cur.push(c);
    i++;
  }
  emit("");
  return parts;
}

// ---------------------------------------------------------------------------
// Folding the claude-cli wrapper (DISPLAY.md, section 6): only the exact service template.
// ---------------------------------------------------------------------------
const WRAP_MID = " 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval ";
const WRAP_TAIL = " && pwd -P >| ";
const WRAP_STDIN = " < /dev/null";

function safePath(p: string): boolean {
  return p.length > 1 && p[0] === "/" && /^[A-Za-z0-9._/-]+$/.test(p);
}
function isSnapshotPath(p: string): boolean {
  if (!safePath(p)) return false;
  const i = p.lastIndexOf("/");
  const dir = p.slice(0, i);
  const file = p.slice(i + 1);
  return basename(dir) === "shell-snapshots" && /^snapshot-bash-[0-9]+-[a-z0-9]+\.sh$/.test(file);
}
function isCwdFile(p: string): boolean {
  return safePath(p) && /^claude-[0-9a-f]+-cwd$/.test(basename(p));
}

export type Wrapper = { kind: "claude-cli"; command: string; snapshot: string; cwdFile: string };

/** claude-cli wrapper exactly by the template: inner command and service paths; otherwise null. */
export function claudeWrapper(argv: string[]): Wrapper | null {
  if (argv.length !== 3 || basename(argv[0]) !== "bash" || argv[1] !== "-c") return null;
  const s = argv[2];
  if (!s.startsWith("source ")) return null;
  const sp = s.indexOf(" ", 7);
  if (sp < 0) return null;
  const snapshot = s.slice(7, sp);
  if (!isSnapshotPath(snapshot) || !s.startsWith(WRAP_MID, sp)) return null;
  let i = sp + WRAP_MID.length;
  // the eval word: only '…' and "'" in a row, '…' first
  let cmd = "";
  let segs = 0;
  for (;;) {
    if (s[i] === "'") {
      const e = s.indexOf("'", i + 1);
      if (e < 0) return null;
      cmd += s.slice(i + 1, e);
      i = e + 1;
      segs++;
    } else if (segs > 0 && s.startsWith(`"'"`, i)) {
      cmd += "'";
      i += 3;
    } else break;
  }
  if (!segs) return null;
  if (s.startsWith(WRAP_STDIN, i)) i += WRAP_STDIN.length;
  if (!s.startsWith(WRAP_TAIL, i)) return null;
  const cwdFile = s.slice(i + WRAP_TAIL.length);
  if (!isCwdFile(cwdFile)) return null;
  return { kind: "claude-cli", command: cmd, snapshot, cwdFile };
}

/** claude-cli wrapper argv around a command, exactly by the template (for tests and mock cards). */
export function claudeWrapArgv(cmd: string, snapshot = "/home/user/.claude/shell-snapshots/snapshot-bash-1790452891926-09cuz2.sh", cwdFile = "/home/user/.openclaw/tmp/claude-e51c-cwd"): string[] {
  const word = `'${cmd.replace(/'/g, `'"'"'`)}'`;
  const heredoc = /<<-?\s*['"]?\w/.test(cmd);
  return ["/bin/bash", "-c", `source ${snapshot}${WRAP_MID}${word}${heredoc ? "" : WRAP_STDIN}${WRAP_TAIL}${cwdFile}`];
}

// ---------------------------------------------------------------------------
// Display model
// ---------------------------------------------------------------------------
export type Form = "wrapper" | "shell" | "argv";

/** Command part: `mixed` holds the mixed runs of letters in its `text` (where exactly a letter was swapped). */
export type Part = { text: string; sep: Sep; danger: string[]; flags: Flag[]; mixed: MixedRun[] };

export type CommandView = {
  form: Form;
  wrapper: "claude-cli" | null;
  shell: string | null;
  /** Command inside the wrapper / `sh -c` script / shell-quoted argv, as is (no sanitizer). */
  command: string;
  parts: Part[];
  /** Indices of the parts visible in the collapsed card; the rest ("N more") are safe and stand in safe chains. */
  visible: number[];
  hidden: number;
  /** Part for the one-line summary: first visible with a rule or flag, else first with eval, else 0; null: no parts. */
  headline: number | null;
  danger: string[];
  flags: Flag[];
  /** Mixed words behind the card's mixedScript flag: from argv, exe and the chain, no repeats. */
  mixed: MixedWord[];
  delegating: string | null;
  dangerous: boolean;
};

export type ViewInput = { argv: string[]; exe?: string; cwd?: string; chain?: string[] };

const SHELLS = new Set(["sh", "bash", "dash", "zsh", "ksh", "ash"]);
const PLAIN_ARG = /^[A-Za-z0-9_@%+=:,./-]+$/;

export function shellQuote(argv: string[]): string {
  return argv.map((x) => (PLAIN_ARG.test(x) ? x : `'${x.replace(/'/g, `'\\''`)}'`)).join(" ");
}

function orderRules(ids: Iterable<string>): string[] {
  const set = new Set(ids);
  return RULES.filter((r) => set.has(r.id)).map((r) => r.id);
}

function unionFlags(...lists: Flag[][]): Flag[] {
  const set = new Set<Flag>();
  for (const l of lists) for (const f of l) set.add(f);
  return sortFlags(set);
}

/** Script parts with flags and rules; attribution of the card rules by pipelines. */
function partsOf(raws: { raw: string; sep: Sep; norm: string }[], cardDanger: string[]): { parts: Part[]; showAll: boolean } {
  const parts: Part[] = raws.map((r) => {
    const sz = sanitize(r.raw);
    return { text: sz.text, sep: r.sep, danger: matchRules(r.norm), flags: unionFlags(sz.flags, tokenFlags(r.raw)), mixed: mixedRuns(r.raw) };
  });
  // pipelines: consecutive parts joined by "|"
  const pipes: number[][] = [];
  let curPipe: number[] = [];
  raws.forEach((r, i) => {
    curPipe.push(i);
    if (r.sep !== "|") {
      pipes.push(curPipe);
      curPipe = [];
    }
  });
  if (curPipe.length) pipes.push(curPipe);
  let showAll = false;
  for (const id of cardDanger) {
    if (parts.some((p) => p.danger.includes(id))) continue;
    const re = ruleRe(RULES.find((r) => r.id === id) as Rule);
    let found = false;
    for (const pipe of pipes) {
      if (pipe.length < 2) continue;
      if (re.test(pipe.map((i) => raws[i].norm).join(" | "))) {
        found = true;
        for (const i of pipe) parts[i].danger = orderRules([...parts[i].danger, id]);
      }
    }
    if (!found) showAll = true;
  }
  return { parts, showAll };
}

/** A part with eval: a command inside a string, always visible (but that does not make it dangerous). */
const EVAL_RE = /(^|[\s;&|(])eval(\s|$)/;

/** Operators that continue a chain: a pipe (`|`, `|&`) and `&&`, `||`. `;`, `&` and a newline end it. */
const CHAIN_SEPS = new Set<Sep>(["|", "&&", "||"]);

/**
 * Chains with a dangerous part: if at least one part of a chain has a rule or a flag, all its parts
 * are shown in full (otherwise `tar cz ~/.ssh | 1 more | nc …` hides what stands between them).
 */
function riskyChains(parts: Part[], risky: (i: number) => boolean): boolean[] {
  const out = parts.map(() => false);
  let start = 0;
  for (let i = 0; i < parts.length; i++) {
    if (CHAIN_SEPS.has(parts[i].sep) && i < parts.length - 1) continue;
    let any = false;
    for (let k = start; k <= i; k++) any = any || risky(k);
    if (any) for (let k = start; k <= i; k++) out[k] = true;
    start = i + 1;
  }
  return out;
}

function visibility(parts: Part[], norms: string[], showAll: boolean): { visible: number[]; hidden: number; headline: number | null } {
  const n = parts.length;
  const risky = (i: number) => parts[i].danger.length > 0 || parts[i].flags.length > 0;
  const hasEval = (i: number) => EVAL_RE.test(norms[i]);
  const inRiskyChain = riskyChains(parts, risky);
  const all = parts.map((_, i) => i);
  const visible = showAll || n <= 4 ? all : all.filter((i) => i < 2 || i === n - 1 || inRiskyChain[i] || hasEval(i));
  const headline = n === 0 ? null : visible.find(risky) ?? visible.find(hasEval) ?? 0;
  return { visible, hidden: n - visible.length, headline };
}

/** Exec envelope display: argv, exe, cwd and the process chain (all signed envelope fields). */
export function commandView(input: ViewInput): CommandView {
  const argv = input.argv;
  const exe = input.exe ?? "";
  const wrapper = claudeWrapper(argv);
  let form: Form;
  let shell: string | null = null;
  let command: string;
  let raws: { raw: string; sep: Sep; norm: string }[];
  let cardDanger: string[];
  if (wrapper || (argv.length === 3 && SHELLS.has(basename(argv[0])) && /^-[eilux]*c[eilux]*$/.test(argv[1]))) {
    form = wrapper ? "wrapper" : "shell";
    shell = basename(argv[0]);
    command = wrapper ? wrapper.command : argv[2];
    raws = splitShell(command).map((p) => ({ ...p, norm: normalizeForRules(p.raw) }));
    cardDanger = matchRules(normalizeForRules(command));
  } else {
    form = "argv";
    command = shellQuote(argv);
    const texts = [argv.join(" ")];
    if (argv.length && exe) texts.push([basename(exe), ...argv.slice(1)].join(" "));
    cardDanger = orderRules(texts.flatMap((t) => matchRules(normalizeForRules(t))));
    raws = argv.length ? [{ raw: command, sep: "", norm: normalizeForRules(texts[0]) }] : [];
  }
  let { parts, showAll } = partsOf(raws, cardDanger);
  if (form === "argv" && parts.length) {
    parts[0].danger = cardDanger;
    parts[0].flags = unionFlags(parts[0].flags, ...argv.map(tokenFlags), programFlags(argv[0]));
    showAll = false;
  }
  const { visible, hidden, headline } = visibility(parts, raws.map((r) => r.norm), showAll);
  const flags = unionFlags(
    ...argv.map((a) => sanitize(a).flags),
    ...argv.map(tokenFlags),
    argv.length ? programFlags(argv[0]) : [],
    exe ? programFlags(exe) : [],
    sanitize(input.cwd ?? "").flags,
    ...(input.chain ?? []).map(programFlags),
  );
  const delegating = delegatingOf(argv, exe);
  return {
    form,
    wrapper: wrapper ? "claude-cli" : null,
    shell,
    command,
    parts,
    visible,
    hidden,
    headline,
    danger: cardDanger,
    flags,
    mixed: mixedWords([...argv, exe, ...(input.chain ?? [])]),
    delegating,
    dangerous: cardDanger.length > 0 || flags.length > 0 || delegating !== null,
  };
}

/**
 * A command as text without argv (OpenClaw gateway exec cards, mock cards): the same split into
 * parts, flags and rules as for an `sh -c` script. Not in the vectors: wardend always has argv.
 */
export function textView(command: string): CommandView {
  const raws = splitShell(command).map((p) => ({ ...p, norm: normalizeForRules(p.raw) }));
  const cardDanger = matchRules(normalizeForRules(command));
  const { parts, showAll } = partsOf(raws, cardDanger);
  const { visible, hidden, headline } = visibility(parts, raws.map((r) => r.norm), showAll);
  const flags = unionFlags(sanitize(command).flags, tokenFlags(command));
  return { form: "shell", wrapper: null, shell: null, command, parts, visible, hidden, headline, danger: cardDanger, flags, mixed: mixedWords([command]), delegating: null, dangerous: cardDanger.length > 0 || flags.length > 0 };
}

/** One-line summary: the headline part and "+N" if there is more than one part. */
export function headlineText(v: CommandView): string {
  if (v.headline === null) return "";
  const t = v.parts[v.headline].text;
  return v.parts.length > 1 ? `${t}  (+${v.parts.length - 1})` : t;
}

// ---------------------------------------------------------------------------
// Exec environment (DISPLAY.md, section 7a): variables that change program behavior. wardend makes
// the choice; everything that came in the signed envelope is shown here, in envp order.
// ---------------------------------------------------------------------------
/** Envelope env entry: cut is how many value code points wardend cut off (absent: not truncated). */
export type EnvVar = { name: string; value: string; cut?: number };
export type EnvFlag = "control" | "bidi" | "invisible" | "truncated" | "duplicate";
/** Entry for display: name and value sanitized, cut 0: not truncated, loader: loads code into the program. */
export type EnvEntry = { name: string; value: string; cut: number; flags: EnvFlag[]; loader: boolean };
/** `loader`: names of the loader variables with a non-empty value, in order of first appearance. */
export type EnvView = { entries: EnvEntry[]; loader: string[]; dangerous: boolean };

/** Dynamic loader variables: with a non-empty value, foreign code gets into the program. */
export const LOADER_VARS = ["LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"];

export function envView(env: EnvVar[]): EnvView {
  const count = new Map<string, number>();
  for (const e of env) count.set(e.name, (count.get(e.name) ?? 0) + 1);
  const loader: string[] = [];
  const entries = env.map((e): EnvEntry => {
    const n = sanitize(e.name);
    const v = sanitize(e.value);
    const cut = typeof e.cut === "number" && e.cut > 0 ? e.cut : 0;
    const flags: EnvFlag[] = unionFlags(n.flags, v.flags) as EnvFlag[];
    if (cut > 0) flags.push("truncated");
    if ((count.get(e.name) ?? 0) > 1) flags.push("duplicate");
    const isLoader = LOADER_VARS.includes(e.name) && e.value !== "";
    if (isLoader && !loader.includes(e.name)) loader.push(e.name);
    return { name: n.text, value: v.text, cut, flags, loader: isLoader };
  });
  return { entries, loader, dangerous: entries.some((x) => x.loader || x.flags.length > 0) };
}
