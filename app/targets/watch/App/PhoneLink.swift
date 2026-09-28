// SPDX-License-Identifier: GPL-3.0-or-later
// WatchConnectivity on the watch: the only thing the phone sends is a wardend pairing link (the
// watch has no camera). Everything after that (key, pairing, push token, approvals) the watch does
// itself over HTTPS. The watch reports the pairing state back so the phone can show the fingerprint
// to compare with `wardend pair list`.
//
// Messages (dictionaries):
//   phone → watch  {type: "pairLink", link: "wardenclaw://pair?…", name: "Apple Watch"}
//                  via sendMessage (watch app open) or transferUserInfo (queued, delivered later)
//   watch → phone  {type: "pairStatus", status, fingerprint?, host, error?}
import Foundation
import WatchConnectivity

final class PhoneLink: NSObject, WCSessionDelegate {
  static let shared = PhoneLink()

  func activate() {
    guard WCSession.isSupported() else { return }
    WCSession.default.delegate = self
    WCSession.default.activate()
  }

  /// Tell the phone how pairing went (best effort: queued if the phone app is not running).
  func report(status: String, fingerprint: String?, host: String, error: String? = nil) {
    guard WCSession.isSupported(), WCSession.default.activationState == .activated else { return }
    var msg: [String: Any] = ["type": "pairStatus", "status": status, "host": host]
    if let f = fingerprint { msg["fingerprint"] = f }
    if let e = error { msg["error"] = e }
    if WCSession.default.isReachable {
      WCSession.default.sendMessage(msg, replyHandler: nil) { _ in WCSession.default.transferUserInfo(msg) }
    } else {
      WCSession.default.transferUserInfo(msg)
    }
  }

  private func handle(_ msg: [String: Any], reply: (([String: Any]) -> Void)?) {
    guard msg["type"] as? String == "pairLink", let link = msg["link"] as? String else {
      reply?(["ok": false, "error": "unknown message"])
      return
    }
    let name = (msg["name"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "Apple Watch"
    // Answer at once (the phone's reply handler times out); the result follows as pairStatus.
    reply?(["ok": true])
    Task { @MainActor in
      WatchModel.shared.offer(link: link, name: String(name.prefix(64)))
    }
  }

  // MARK: WCSessionDelegate

  func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {}

  func session(_ session: WCSession, didReceiveMessage message: [String: Any], replyHandler: @escaping ([String: Any]) -> Void) {
    handle(message, reply: replyHandler)
  }

  func session(_ session: WCSession, didReceiveMessage message: [String: Any]) {
    handle(message, reply: nil)
  }

  func session(_ session: WCSession, didReceiveUserInfo userInfo: [String: Any] = [:]) {
    handle(userInfo, reply: nil)
  }
}
