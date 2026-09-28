// SPDX-License-Identifier: GPL-3.0-or-later
// Screens of the watch app: pairing state, the list of pending requests, a card, and the approve
// screen (hold about 1.5 s, or turn the Digital Crown to the end). Deny is a single button.
import SwiftUI
import WatchKit

struct RootView: View {
  @EnvironmentObject var model: WatchModel

  var body: some View {
    Group {
      switch model.phase {
      case .unpaired: UnpairedView()
      case .pairing: PairingView()
      case .paired: CardListView()
      }
    }
    .alert(L.t("New pairing link"), isPresented: Binding(get: { model.offered != nil }, set: { if !$0 { model.offered = nil } })) {
      Button(L.t("Replace"), role: .destructive) { model.acceptOffered() }
      Button(L.t("Ignore"), role: .cancel) { model.offered = nil }
    } message: {
      Text(L.t("The iPhone sent a link for \(model.offered?.host ?? "?"). Pair the watch with it instead of the current server?"))
    }
  }
}

struct UnpairedView: View {
  @EnvironmentObject var model: WatchModel

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 8) {
        Text("WardenClaw").font(.headline)
        Text(L.t("Pair this watch from the iPhone app: Mode → Apple Watch → Pair the watch. The watch creates its own key and becomes a separate trusted device in wardend."))
          .font(.footnote)
        if let e = model.lastError { Text(e).font(.footnote).foregroundStyle(.red) }
      }
    }
  }
}

struct PairingView: View {
  @EnvironmentObject var model: WatchModel

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 8) {
        Text(L.t("Waiting for the server")).font(.headline)
        if let id = model.deviceId {
          Text(WardenProtocol.fingerprint(id)).font(.system(.body, design: .monospaced))
        }
        Text(L.t("On the server run `wardend pair list`, compare this fingerprint, then `wardend pair approve <id>`."))
          .font(.footnote)
        if let host = model.pairing?.host, !host.isEmpty { Text(host).font(.footnote).foregroundStyle(.secondary) }
        if let e = model.lastError { Text(e).font(.footnote).foregroundStyle(.red) }
        Button(L.t("Cancel pairing"), role: .destructive) {
          Task { await model.unpairLocally() }
        }
      }
    }
  }
}

struct CardListView: View {
  @EnvironmentObject var model: WatchModel
  @State private var path: [String] = []

  var body: some View {
    NavigationStack(path: $path) {
      list
    }
    // after a decision go back to the list, not to an "already decided" screen
    .onChange(of: model.decided) { _, _ in path = [] }
  }

  private var list: some View {
    List {
      if model.cards.isEmpty {
        Text(model.online ? L.t("No pending requests") : L.t("Connecting…"))
          .foregroundStyle(.secondary)
      }
      ForEach(model.cards) { card in
        NavigationLink(value: card.id) {
          VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .top, spacing: 4) {
              if card.dangerous { Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(.red) }
              Text(card.command).font(.system(.footnote, design: .monospaced)).lineLimit(3)
            }
            HStack(spacing: 4) {
              if card.hardwareRequired { Image(systemName: "key.fill").foregroundStyle(.orange) }
              if card.problem != nil { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red) }
              Text(card.host).font(.caption2).foregroundStyle(.secondary)
              Spacer(minLength: 2)
              TtlText(expiresAt: card.expiresAt)
            }
          }
        }
        .listItemTint(card.dangerous ? .red : nil)
      }
      if let e = model.lastError {
        Text(e).font(.caption2).foregroundStyle(.red)
      }
      Section {
        NavigationLink(value: "settings") { Text(L.t("Settings")).foregroundStyle(.secondary) }
      }
    }
    .navigationTitle("WardenClaw")
    .navigationDestination(for: String.self) { id in
      if id == "settings" {
        SettingsView()
      } else if let c = model.cards.first(where: { $0.id == id }) {
        CardView(card: c)
      } else {
        Text(L.t("Already decided or expired")).foregroundStyle(.secondary)
      }
    }
    .onChange(of: model.openCardId) { _, id in
      guard let id = id else { return }
      model.openCardId = nil
      path = [id]
    }
  }
}

/// Time left until wardend denies by itself (the record's expiresAt); red in the last 20 s.
struct TtlText: View {
  let expiresAt: Int64

  var body: some View {
    if expiresAt > 0 {
      let deadline = Date(timeIntervalSince1970: Double(expiresAt) / 1000)
      TimelineView(.periodic(from: .now, by: 1)) { ctx in
        let left = deadline.timeIntervalSince(ctx.date)
        if left <= 0 {
          Text(L.t("expiring")).font(.caption2).foregroundStyle(.red)
        } else {
          Text(timerInterval: ctx.date...deadline, countsDown: true)
            .font(.caption2.monospacedDigit())
            .foregroundStyle(left < 20 ? Color.red : Color.secondary)
        }
      }
    }
  }
}

/// A sanitized text with the odd letters of mixed runs marked (DISPLAY.md, section 3): the letter
/// underlined in orange and its alphabet after it, `Sо⟨Cyr.⟩ns`. Built by Text interpolation.
func markedText(_ text: String, _ runs: [Display.MixedRun]) -> Text {
  var out = Text(verbatim: "")
  for s in Display.markOdd(text, runs) {
    if let o = s.odd {
      let letter: Text = Text(verbatim: s.text).underline().bold().foregroundStyle(Color.orange)
      let label: Text = Text(verbatim: "⟨" + CardText.scriptShort(o.script) + "⟩").font(.system(size: 9)).foregroundStyle(Color.orange)
      out = Text("\(out)\(letter)\(label)")
    } else {
      out = Text("\(out)\(Text(verbatim: s.text))")
    }
  }
  return out
}

/// A part of the command (protocol/DISPLAY.md): risky parts in red, always visible; a spoofed letter
/// is marked where it stands.
struct PartRow: View {
  let part: Display.Part

  var body: some View {
    let risky = !part.danger.isEmpty || !part.flags.isEmpty
    let sep = part.sep.isEmpty || part.sep == "\n" ? "" : "  " + part.sep
    HStack(alignment: .top, spacing: 3) {
      Rectangle().fill(risky ? Color.red : Color.gray.opacity(0.4)).frame(width: 2)
      Text("\(markedText(part.text, part.mixed))\(Text(verbatim: sep))")
        .font(.system(.caption, design: .monospaced))
        .foregroundStyle(risky ? Color.red : Color.primary)
    }
  }
}

/// An entry of the signed env (DISPLAY.md 7a): a loader variable or a flagged entry in red with what
/// is wrong; a value cut by wardend ends with "… (+N)". A long value is folded, one tap shows it
/// whole (up to 1024 code points).
struct EnvRow: View {
  let entry: Display.EnvEntry
  @State private var whole = false

  var body: some View {
    let risky = entry.loader || !entry.flags.isEmpty
    let value = Array(entry.value.unicodeScalars)
    let folded = !whole && value.count > 120
    let shown = folded ? Display.string(Array(value.prefix(100))) + "…" : entry.value
    VStack(alignment: .leading, spacing: 1) {
      HStack(alignment: .top, spacing: 3) {
        Rectangle().fill(risky ? Color.red : Color.gray.opacity(0.4)).frame(width: 2)
        Text(verbatim: entry.name + "=" + shown + (entry.cut > 0 ? " … (+\(entry.cut))" : ""))
          .font(.system(.caption2, design: .monospaced))
          .foregroundStyle(risky ? Color.red : Color.primary)
      }
      if folded {
        Button(L.t("Whole value (\(value.count))")) { whole = true }.font(.caption2)
      }
      if entry.loader {
        Text(L.t("loader: loads other code into the program")).font(.system(size: 10)).foregroundStyle(.red)
      }
      ForEach(entry.flags, id: \.self) { f in
        Text(CardText.envFlag(f)).font(.system(size: 10)).foregroundStyle(.red)
      }
    }
  }
}

struct CardView: View {
  @EnvironmentObject var model: WatchModel
  @Environment(\.dismiss) private var dismiss
  let card: Card
  @State private var allParts = false
  @State private var showArgv = false
  @State private var allEnv = false

  var body: some View {
    let v = card.view
    let shown = allParts ? Array(v.parts.indices) : v.visible
    let ruleVerdict = CardText.ruleVerdict(v)
    ScrollView {
      VStack(alignment: .leading, spacing: 6) {
        if card.dangerous {
          VStack(alignment: .leading, spacing: 2) {
            Label(L.t("Dangerous"), systemImage: "exclamationmark.octagon.fill").font(.caption.bold()).foregroundStyle(.red)
            ForEach(CardText.reasons(card), id: \.self) { Text($0).font(.caption2) }
          }
          .padding(6)
          .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.red, lineWidth: 2))
        }

        // Signed facts: fields of the envelope, covered by the digest.
        Text(L.t("Signed facts")).font(.caption2.bold()).foregroundStyle(.secondary)
        Text(CardText.form(v)).font(.caption2).foregroundStyle(.secondary)
        // "… N more" where parts are hidden, so the visible ones never read as one command
        ForEach(Array(shown.enumerated()), id: \.offset) { k, i in
          let gap = k == 0 ? i : i - shown[k - 1] - 1
          if gap > 0 {
            Text(L.t("… \(gap) more")).font(.caption2).foregroundStyle(.secondary)
          }
          PartRow(part: v.parts[i])
        }
        if v.parts.isEmpty { Text(L.t("(empty argv)")).font(.caption2) }
        if v.hidden > 0 && !allParts {
          Button(L.t("\(v.hidden) more (no rules, no flags)")) { allParts = true }
            .font(.caption2)
        }
        HStack(spacing: 4) {
          Text(L.t("No answer, then deny:")).font(.caption2)
          TtlText(expiresAt: card.expiresAt)
        }
        Text(L.t("Allowing covers everything this command starts while it runs."))
          .font(.caption2).foregroundStyle(.orange)
        if !card.cwd.isEmpty { Label(Display.sanitizeText(card.cwd), systemImage: "folder").font(.caption2) }
        Label(Display.sanitizeText(card.exe), systemImage: "gearshape").font(.caption2)
        if let uid = card.uid { Text("uid \(uid)" + (uid == 0 ? " (root)" : "")).font(.caption2) }
        if !card.host.isEmpty { Label(Display.sanitizeText(card.host), systemImage: "server.rack").font(.caption2) }
        Button(showArgv ? L.t("Hide argv") : L.t("Full argv (\(card.argv.count))")) { showArgv.toggle() }
          .font(.caption2)
        if showArgv {
          ForEach(Array(card.argv.enumerated()), id: \.offset) { i, a in
            Text("[\(i)] " + Display.sanitizeText(a)).font(.system(.caption2, design: .monospaced))
          }
          ForEach(Array(card.chain.enumerated()), id: \.offset) { i, e in
            Text(String(repeating: " ", count: i) + "↑ " + Display.sanitizeText(e)).font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
          }
        }

        // Environment (signed, DISPLAY.md 7a): folded, loader and flagged entries in full and the
        // rest as a count; unfolded, all of them.
        if !card.env.entries.isEmpty {
          let env = card.env.entries
          let risky = env.indices.filter { env[$0].loader || !env[$0].flags.isEmpty }
          let shownEnv = allEnv ? Array(env.indices) : risky
          Text(L.t("Environment")).font(.caption2.bold()).foregroundStyle(.secondary)
          ForEach(shownEnv, id: \.self) { i in EnvRow(entry: env[i]) }
          if shownEnv.count < env.count {
            Button(L.t("\(env.count - shownEnv.count) more")) { allEnv = true }.font(.caption2)
          }
        }

        // Assessment, not signed: a rule's verdict and a model's opinion, each under its own name
        // (a matched rule is not a model's opinion). The watch runs no model of its own.
        if ruleVerdict != nil || card.judgeRisk != nil || card.judgeText != nil {
          VStack(alignment: .leading, spacing: 2) {
            Text(L.t("Assessment, not signed")).font(.caption2.bold()).foregroundStyle(.secondary)
            if let r = ruleVerdict { Text(L.t("Rule: ") + r).font(.caption2) }
            if card.judgeRisk != nil || card.judgeText != nil {
              Text(L.t("Model (from the server): ") + (card.judgeRisk.map { "\($0)/100" } ?? L.t("no score"))).font(.caption2)
              if let t = card.judgeText { Text(Display.sanitizeText(t)).font(.caption2) }
            }
          }
          .foregroundStyle(.secondary)
        }

        // Not confirmed: meta from the transport, not in the digest.
        if card.cls != nil || card.rule != nil || card.delegating != nil || card.insideRoot != nil {
          VStack(alignment: .leading, spacing: 2) {
            Text(L.t("Not confirmed (from the server, not signed)")).font(.caption2.bold()).foregroundStyle(.secondary)
            if let cls = card.cls { Text(riskText(cls)).font(.caption2) }
            if let r = card.rule, !r.isEmpty { Text(L.t("Server rule: ") + Display.sanitizeText(r)).font(.caption2) }
            if let d = card.delegating, !d.isEmpty { Text(Display.sanitizeText(d)).font(.caption2) }
            if let p = card.insideRoot { Text(L.t("Inside an approved tree (root pid \(p))")).font(.caption2) }
          }
          .foregroundStyle(.secondary)
        }

        if let p = card.problem {
          Text(p + L.t(". Only deny is possible.")).font(.caption).foregroundStyle(.red)
        }
        if card.hardwareRequired {
          Text(L.t("Needs the YubiKey: approve on the iPhone.")).font(.caption).foregroundStyle(.orange)
        }
        if card.canApprove {
          NavigationLink {
            ApproveView(card: card)
          } label: {
            Label(L.t("Approve…"), systemImage: "checkmark.shield")
          }
          .tint(card.dangerous ? .orange : .green)
        }
        Button(role: .destructive) {
          Task {
            if await model.deny(card) { dismiss() }
          }
        } label: {
          Label(L.t("Deny"), systemImage: "xmark")
        }
        .disabled(model.busyCardId == card.id)
      }
    }
    .navigationTitle(Display.basename(card.exe).isEmpty ? "exec" : Display.sanitizeText(Display.basename(card.exe)))
  }

  private func riskText(_ cls: String) -> String {
    switch cls {
    case "root": return L.t("New process tree (root)")
    case "delegating": return L.t("Delegating: runs code on someone's behalf")
    case "inherit": return L.t("Inside an approved tree")
    default: return Display.sanitizeText(cls)
    }
  }
}

/// Approve with intent: hold the button for 1.5 s, or turn the Digital Crown all the way.
/// Nothing here reacts to a tap or to the double tap gesture. Crown progress falls back to zero
/// after 2 s without turning, so a sleeve cannot finish a half-turned approval later.
struct ApproveView: View {
  @EnvironmentObject var model: WatchModel
  @Environment(\.dismiss) private var dismiss
  let card: Card

  @State private var hold: Double = 0
  @State private var crown: Double = 0
  @State private var crownTick = 0
  @State private var done = false
  private let holdSeconds = 1.5

  var body: some View {
    VStack(spacing: 6) {
      if card.dangerous {
        Label(L.t("Dangerous"), systemImage: "exclamationmark.octagon.fill").font(.caption2.bold()).foregroundStyle(.red)
      }
      Text(card.command).font(.system(.caption, design: .monospaced)).lineLimit(3)
      ZStack {
        Circle().stroke(Color.gray.opacity(0.3), lineWidth: 6)
        Circle()
          .trim(from: 0, to: max(hold, crown))
          .stroke(card.dangerous ? Color.orange : Color.green, style: StrokeStyle(lineWidth: 6, lineCap: .round))
          .rotationEffect(.degrees(-90))
        Image(systemName: done ? "checkmark" : "hand.tap").font(.title2)
      }
      .frame(width: 70, height: 70)
      .contentShape(Circle())
      .onLongPressGesture(minimumDuration: holdSeconds, maximumDistance: 30) {
        submit()
      } onPressingChanged: { pressing in
        if pressing {
          withAnimation(.linear(duration: holdSeconds)) { hold = 1 }
        } else if !done {
          withAnimation(.easeOut(duration: 0.2)) { hold = 0 }
        }
      }
      HStack(spacing: 4) {
        Text(L.t("Hold, or turn the Crown to the end"))
          .font(.caption2)
          .multilineTextAlignment(.center)
          .foregroundStyle(.secondary)
      }
      TtlText(expiresAt: card.expiresAt)
    }
    .focusable(true)
    .digitalCrownRotation($crown, from: 0, through: 1, by: 0.02, sensitivity: .low, isContinuous: false, isHapticFeedbackEnabled: true)
    .onChange(of: crown) { _, v in
      if v >= 0.999 {
        submit()
        return
      }
      crownTick += 1
      let tick = crownTick
      Task { @MainActor in
        try? await Task.sleep(nanoseconds: 2_000_000_000)
        if tick == crownTick && !done && crown > 0 { withAnimation(.easeOut(duration: 0.3)) { crown = 0 } }
      }
    }
    .disabled(done || model.busyCardId == card.id)
    .navigationTitle(L.t("Approve"))
  }

  private func submit() {
    guard !done else { return }
    done = true
    Task {
      if await model.approve(card) {
        dismiss()
      } else {
        done = false
        hold = 0
        crown = 0
      }
    }
  }
}

struct SettingsView: View {
  @EnvironmentObject var model: WatchModel
  @State private var confirm = false

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 6) {
        if let p = model.pairing {
          Text(p.host.isEmpty ? p.url : p.host).font(.headline)
          Text(p.url).font(.caption2).foregroundStyle(.secondary)
        }
        if let id = model.deviceId {
          Text(L.t("This watch")).font(.caption)
          Text(WardenProtocol.fingerprint(id)).font(.system(.caption, design: .monospaced))
        }
        Text(model.pairing?.pushToken != nil ? L.t("Notifications: on") : L.t("Notifications: not registered"))
          .font(.caption2).foregroundStyle(.secondary)
        Button(L.t("Unpair"), role: .destructive) { confirm = true }
      }
    }
    .confirmationDialog(L.t("Delete the key and the server from the watch? Revoke the device on the server too: wardend pair revoke."),
                        isPresented: $confirm) {
      Button(L.t("Unpair"), role: .destructive) { Task { await model.unpairLocally() } }
    }
  }
}
