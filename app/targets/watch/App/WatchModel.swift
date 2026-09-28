// SPDX-License-Identifier: GPL-3.0-or-later
// State of the watch app: pairing, pending cards from wardend, decisions, push registration.
//
// The watch is its own trusted device in wardend (alg es256), not a mirror of the phone. It may
// sign `allow` only for a card that passes the same check as the phone app and wardenctl
// (WardenProtocol.checkPending: strict 14-field envelope v1, supervisorId equal to the pinned one,
// digest recomputed, id == "wd-" + digest[:32]) and that does not require the hardware key
// (meta.hardware.required: the watch has no YubiKey, approve those on the phone). `deny` is always
// allowed: it only needs the record's id and digest.
import Foundation
import SwiftUI
import WatchKit

struct Card: Identifiable, Equatable {
  let id: String
  let digest: String
  /// How the envelope is shown (protocol/DISPLAY.md): parts, rules, flags, delegating launch.
  let view: Display.View
  let argv: [String]
  let cwd: String
  let host: String
  let exe: String
  let uid: Int64?
  /// ppidChain exes: the caller first, then its parents.
  let chain: [String]
  /// The signed `env` as shown (DISPLAY.md 7a): loader variables and flagged entries make the card dangerous.
  let env: Display.EnvView
  // meta.* is not in the digest: shown as unconfirmed, used only to add caution, never to lower it.
  /// meta.class: root | delegating | inherit
  let cls: String?
  let rule: String?
  let delegating: String?
  let insideRoot: Int64?
  /// meta.judge / meta.opinion: someone else's opinion from the transport, not the owner's judge.
  let judgeRisk: Int?
  let judgeText: String?
  let hardwareRequired: Bool
  /// nil: the envelope checks out and the watch may sign allow; otherwise why not.
  let problem: String?
  let expiresAt: Int64

  /// One line for the list: the headline part (a risky one first) and "(+N)".
  var command: String { view.headlineText }
  var dangerous: Bool { view.dangerous || env.dangerous || cls == "delegating" }
  var canApprove: Bool { problem == nil && !hardwareRequired }

  static func from(_ item: JSONValue, pinnedSupervisorId: String) -> Card? {
    guard let id = item["id"]?.stringValue, let digest = item["digest"]?.stringValue else { return nil }
    let env = item["envelope"]
    let meta = item["meta"]
    var problem: String?
    var parsed: WardenProtocol.ExecEnvelope?
    switch WardenProtocol.checkPending(id: id, digest: digest, envelope: env, pinnedSupervisorId: pinnedSupervisorId) {
    case let .success(e): parsed = e
    case let .failure(f):
      switch f {
      case .notV1: problem = L.t("The request is not a v1 exec envelope")
      case .otherSupervisor: problem = L.t("The request comes from another server")
      case let .digestMismatch(r, c): problem = L.t("Digest mismatch (\(r) vs \(c))")
      case .idMismatch: problem = L.t("The id does not match the digest")
      }
    }
    // Shown even when the check failed (from the raw envelope), but then only deny is possible.
    let argv = parsed?.argv ?? env?["argv"]?.arrayValue?.compactMap { $0.stringValue } ?? []
    let exe = parsed?.exe ?? env?["exe"]?.stringValue ?? ""
    let cwd = parsed?.cwd ?? env?["cwd"]?.stringValue ?? ""
    let chain = parsed?.ppidChain.map { $0.exe } ?? env?["ppidChain"]?.arrayValue?.compactMap { $0["exe"]?.stringValue } ?? []
    let envVars = parsed?.env ?? env?["env"]?.arrayValue?.compactMap { e -> WardenProtocol.EnvVar? in
      guard let n = e["name"]?.stringValue, let v = e["value"]?.stringValue else { return nil }
      return WardenProtocol.EnvVar(name: n, value: v, cut: e["cut"]?.safeInteger)
    } ?? []
    let judge = meta?["judge"] ?? meta?["opinion"]
    let hw = meta?["hardware"]?["required"]?.boolValue == true
    // wardend sends meta.delegating as the rule's text and meta.insideRoot as the root's pid
    let deleg = meta?["delegating"]?.stringValue ?? (meta?["delegating"]?.boolValue == true ? L.t("yes") : nil)
    return Card(
      id: id, digest: digest,
      view: Display.commandView(argv: argv, exe: exe, cwd: cwd, chain: chain),
      argv: argv,
      cwd: cwd,
      host: parsed?.host ?? env?["requester"]?["host"]?.stringValue ?? "",
      exe: exe,
      uid: parsed?.uid ?? env?["uid"]?.safeInteger,
      chain: chain,
      env: Display.envView(envVars),
      cls: meta?["class"]?.stringValue,
      rule: meta?["rule"]?.stringValue,
      delegating: deleg,
      insideRoot: meta?["insideRoot"]?.safeInteger,
      judgeRisk: (judge?["risk"]?.safeInteger).map { Int($0) },
      judgeText: judge?["summary"]?.stringValue ?? judge?["reason"]?.stringValue ?? judge?["verdict"]?.stringValue,
      hardwareRequired: hw,
      problem: problem,
      expiresAt: item["expiresAt"]?.safeInteger ?? 0
    )
  }
}

/// UI strings: English only; t() is the single hook for a future localization.
enum L {
  static func t(_ en: String) -> String { en }
}

@MainActor
final class WatchModel: ObservableObject {
  static let shared = WatchModel()

  enum Phase: Equatable {
    case unpaired
    /// waiting for `wardend pair approve` on the server
    case pairing
    case paired
  }

  @Published private(set) var phase: Phase = .unpaired
  @Published private(set) var pairing: Pairing?
  @Published private(set) var deviceId: String?
  @Published private(set) var cards: [Card] = []
  @Published private(set) var online = false
  @Published var lastError: String?
  @Published var busyCardId: String?
  /// Card to open (from a notification's "Open" action).
  @Published var openCardId: String?
  /// Bumped after every accepted decision: the list pops back to itself (no "already decided" screen).
  @Published private(set) var decided = 0

  private var client: WardendClient?
  private var seq: Int64 = 0
  private var pollTask: Task<Void, Never>?
  private var pairTask: Task<Void, Never>?
  private var active = false

  private init() {}

  // MARK: lifecycle

  func start() {
    guard let p = Pairing.load(), let key = try? DeviceKey.load() else {
      phase = .unpaired
      return
    }
    pairing = p
    deviceId = key.deviceId
    client = WardendClient(base: p.url, pinnedKey: p.key, device: key)
    phase = p.status == "approved" ? .paired : .pairing
    if phase == .pairing { watchPairStatus() }
    if phase == .paired { WKApplication.shared().registerForRemoteNotifications() }
  }

  /// Scene became active or inactive: long-poll only while the app is on screen.
  func setActive(_ on: Bool) {
    active = on
    if on, phase == .paired { startPolling() } else { stopPolling() }
  }

  // MARK: pairing

  struct OfferedLink: Equatable {
    let link: String
    let name: String
    let host: String
  }

  /// A link that arrived while the watch is already paired: replacing the pairing needs a tap on
  /// the watch (a queued, stale transfer must not silently re-pair it).
  @Published var offered: OfferedLink?

  func offer(link: String, name: String) {
    if phase == .unpaired {
      Task { await pair(with: link, name: name) }
      return
    }
    let host = (try? WardenProtocol.parsePairLink(link).get())?.host ?? "?"
    offered = OfferedLink(link: link, name: name, host: host)
  }

  func acceptOffered() {
    guard let o = offered else { return }
    offered = nil
    Task { await pair(with: o.link, name: o.name) }
  }

  /// A pairing link from the phone (WatchConnectivity). Returns an error text or nil.
  @discardableResult
  func pair(with linkText: String, name: String) async -> String? {
    let link: WardenProtocol.PairLink
    switch WardenProtocol.parsePairLink(linkText) {
    case let .success(l): link = l
    case .failure: return L.t("Not a wardend pairing link")
    }
    guard link.url.lowercased().hasPrefix("https://") else {
      return L.t("The watch needs an https:// address for wardend")
    }
    guard let supervisorId = WardenProtocol.supervisorId(keyB64url: link.key) else { return L.t("Bad server key") }
    await unpairLocally()
    do {
      let key = try DeviceKey.loadOrCreate()
      let c = WardendClient(base: link.url, pinnedKey: link.key, device: key)
      _ = try await c.ping()
      let r = try await c.pair(code: link.code, supervisorId: supervisorId, name: name)
      let p = Pairing(url: link.url, key: link.key, supervisorId: supervisorId, host: r["host"]?.stringValue ?? link.host, name: name,
                      pairId: r["id"]?.stringValue, status: r["status"]?.stringValue ?? "pending", pushToken: nil, pushEnvironment: nil)
      try p.save()
      client = c
      pairing = p
      deviceId = key.deviceId
      phase = p.status == "approved" ? .paired : .pairing
      lastError = nil
      PhoneLink.shared.report(status: p.status, fingerprint: WardenProtocol.fingerprint(key.deviceId), host: p.host)
      if phase == .pairing { watchPairStatus() } else { didPair() }
      return nil
    } catch {
      let msg = describe(error)
      lastError = msg
      PhoneLink.shared.report(status: "error", fingerprint: nil, host: link.host, error: msg)
      return msg
    }
  }

  /// Poll /v1/pair/status until the server operator approves or rejects.
  private func watchPairStatus() {
    pairTask?.cancel()
    pairTask = Task { [weak self] in
      while !Task.isCancelled {
        guard let self = self, let c = self.client, let id = self.pairing?.pairId else { return }
        do {
          let r = try await c.pairStatus(id: id)
          let st = r["status"]?.stringValue ?? "unknown"
          if st != "pending" {
            if var p = self.pairing {
              p.status = st
              try? p.save()
              self.pairing = p
            }
            PhoneLink.shared.report(status: st, fingerprint: self.deviceId.map(WardenProtocol.fingerprint), host: self.pairing?.host ?? "")
            if st == "approved" { self.didPair() } else { self.lastError = L.t("Pairing \(st)") }
            return
          }
        } catch {
          self.lastError = self.describe(error)
        }
        try? await Task.sleep(nanoseconds: 3_000_000_000)
      }
    }
  }

  private func didPair() {
    phase = .paired
    lastError = nil
    WKApplication.shared().registerForRemoteNotifications()
    if active { startPolling() }
  }

  /// Forget the server and the key on the watch (wardend keeps the device until `wardend pair revoke`).
  func unpairLocally() async {
    stopPolling()
    pairTask?.cancel()
    if let c = client, let tok = pairing?.pushToken, phase == .paired {
      _ = try? await c.pushUnregister(token: tok)
    }
    Pairing.delete()
    DeviceKey.delete()
    client = nil
    pairing = nil
    deviceId = nil
    cards = []
    seq = 0
    phase = .unpaired
  }

  // MARK: push

  func didRegister(deviceToken: Data) {
    let token = deviceToken.map { String(format: "%02x", $0) }.joined()
    let env = APNsEnvironment.current
    guard let c = client, phase == .paired, let p0 = pairing else { return }
    if p0.pushToken == token && p0.pushEnvironment == env { return }
    let topic = Bundle.main.bundleIdentifier ?? "com.wardenclaw.app.watchkitapp"
    Task { @MainActor in
      do {
        _ = try await c.pushRegister(token: token, topic: topic, environment: env)
        guard var p = self.pairing else { return }
        p.pushToken = token
        p.pushEnvironment = env
        try? p.save()
        self.pairing = p
      } catch {
        self.lastError = L.t("Push registration: ") + self.describe(error)
      }
    }
  }

  // MARK: pending

  private func startPolling() {
    guard pollTask == nil, let c = client, let pin = pairing?.supervisorId else { return }
    pollTask = Task { [weak self] in
      var backoff: UInt64 = 2
      while !Task.isCancelled {
        guard let self = self else { return }
        do {
          let r = try await c.pending(since: self.seq, waitMs: 25000)
          if Task.isCancelled { return }
          self.seq = r["seq"]?.safeInteger ?? self.seq
          self.cards = (r["pending"]?.arrayValue ?? []).compactMap { Card.from($0, pinnedSupervisorId: pin) }
          self.online = true
          self.lastError = nil
          backoff = 2
        } catch {
          if Task.isCancelled { return }
          self.online = false
          self.lastError = self.describe(error)
          let slow = (error as? WardendError).map { $0.status == 401 || $0.reason == "unsigned_response" } ?? false
          try? await Task.sleep(nanoseconds: (slow ? 30 : backoff) * 1_000_000_000)
          backoff = min(30, backoff * 2)
        }
      }
    }
  }

  private func stopPolling() {
    pollTask?.cancel()
    pollTask = nil
  }

  /// One short fetch (no long poll), e.g. when a notification arrives or is acted upon.
  func refresh() async -> [Card] {
    guard let c = client, let pin = pairing?.supervisorId, phase == .paired else { return cards }
    do {
      let r = try await c.pending(since: 0, waitMs: 0)
      seq = r["seq"]?.safeInteger ?? seq
      cards = (r["pending"]?.arrayValue ?? []).compactMap { Card.from($0, pinnedSupervisorId: pin) }
      online = true
    } catch {
      lastError = describe(error)
    }
    return cards
  }

  // MARK: decisions

  /// Allow: only a card that passed the envelope check and needs no hardware key.
  func approve(_ card: Card) async -> Bool {
    guard card.canApprove else { return false }
    return await decide(card, "allow")
  }

  func deny(_ card: Card) async -> Bool {
    await decide(card, "deny")
  }

  /// "Deny" from a notification: fetch the record (the push carries only its id), sign deny.
  func denyFromNotification(cardId: String) async {
    let list = await refresh()
    guard let card = list.first(where: { $0.id == cardId }) else { return } // already decided or expired
    _ = await deny(card)
  }

  private func decide(_ card: Card, _ decision: String) async -> Bool {
    guard let c = client else { return false }
    busyCardId = card.id
    defer { busyCardId = nil }
    do {
      let r = try await c.decide(id: card.id, digest: card.digest, decision: decision)
      if r["ok"]?.boolValue == true {
        cards.removeAll { $0.id == card.id }
        decided += 1
        WKInterfaceDevice.current().play(decision == "allow" ? .success : .directionDown)
        return true
      }
      let reason = r["reason"]?.stringValue ?? "?"
      lastError = L.t("wardend refused: ") + reason
      if reason == "unknown_pending" || reason == "already_decided" { cards.removeAll { $0.id == card.id } }
      WKInterfaceDevice.current().play(.failure)
      return false
    } catch {
      lastError = describe(error)
      WKInterfaceDevice.current().play(.failure)
      return false
    }
  }

  func describe(_ e: Error) -> String {
    if let w = e as? WardendError {
      if w.reason == "unsigned_response" { return L.t("The reply is not signed by your server for this request") }
      if w.reason == "response_mismatch" { return L.t("The server reply is about another decision") }
      if w.unbound { return L.t("wardend refused before checking the request: ") + w.reason }
      return w.errorDescription ?? w.reason
    }
    if let u = e as? URLError { return u.localizedDescription }
    return (e as? LocalizedError)?.errorDescription ?? String(describing: e)
  }
}

/// Which APNs environment this build's token belongs to: builds signed with a development profile
/// (Xcode Run) get sandbox tokens, TestFlight and App Store builds production ones. The embedded
/// profile (present in development and ad hoc builds) says which; App Store builds have none.
enum APNsEnvironment {
  static var current: String {
    guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
          let data = try? Data(contentsOf: url),
          let text = String(data: data, encoding: .isoLatin1) else { return "production" }
    // the profile is a CMS envelope around a plain XML plist; look for the aps-environment value
    guard let r = text.range(of: "<key>aps-environment</key>") else { return "production" }
    let tail = text[r.upperBound...].prefix(80)
    return tail.contains("development") ? "sandbox" : "production"
  }
}
