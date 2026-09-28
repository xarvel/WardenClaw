// SPDX-License-Identifier: GPL-3.0-or-later
// iPhone side of the Apple Watch pairing: WatchConnectivity only carries a wardend pairing link
// to the watch app (it has no camera to scan the QR code). The watch then creates its own Secure
// Enclave key, pairs with wardend as a separate device (alg es256) and registers its own push token.
// The phone's key is never shared with the watch.
//
//   status()                        → {supported, activated, paired, installed, reachable}
//   sendPairingLink(link, name)     → "delivered" (watch app open, got it now) | "queued" (delivered later)
//   event onWatchStatus             ← {type: "pairStatus", status, fingerprint?, host, error?} from the watch
//                                     and {type: "state"} when pairing/installation/reachability changes
import ExpoModulesCore
import WatchConnectivity

public class AppleWatchModule: Module {
  private lazy var link = WatchLink { [weak self] body in
    self?.sendEvent("onWatchStatus", body)
  }

  public func definition() -> ModuleDefinition {
    Name("AppleWatch")

    Events("onWatchStatus")

    OnCreate {
      self.link.activate()
    }

    Function("status") { () -> [String: Any] in
      self.link.status()
    }

    AsyncFunction("sendPairingLink") { (pairLink: String, name: String, promise: Promise) in
      self.link.send(pairLink: pairLink, name: name, promise: promise)
    }
  }
}

final class WatchLink: NSObject, WCSessionDelegate {
  private let emit: ([String: Any]) -> Void

  init(emit: @escaping ([String: Any]) -> Void) {
    self.emit = emit
  }

  func activate() {
    guard WCSession.isSupported() else { return }
    WCSession.default.delegate = self
    WCSession.default.activate()
  }

  func status() -> [String: Any] {
    guard WCSession.isSupported() else {
      return ["supported": false, "activated": false, "paired": false, "installed": false, "reachable": false]
    }
    let s = WCSession.default
    let on = s.activationState == .activated
    return ["supported": true, "activated": on, "paired": on && s.isPaired, "installed": on && s.isWatchAppInstalled, "reachable": on && s.isReachable]
  }

  func send(pairLink: String, name: String, promise: Promise) {
    guard WCSession.isSupported() else {
      promise.reject("NOT_SUPPORTED", "WatchConnectivity is not available on this device")
      return
    }
    let s = WCSession.default
    guard s.activationState == .activated else {
      promise.reject("NOT_ACTIVATED", "the connection to the watch is not ready yet, try again")
      return
    }
    guard s.isPaired else {
      promise.reject("NOT_PAIRED", "no Apple Watch is paired with this iPhone")
      return
    }
    guard s.isWatchAppInstalled else {
      promise.reject("NOT_INSTALLED", "WardenClaw is not installed on the watch")
      return
    }
    let msg: [String: Any] = ["type": "pairLink", "link": pairLink, "name": name]
    if s.isReachable {
      s.sendMessage(msg, replyHandler: { _ in
        promise.resolve("delivered")
      }, errorHandler: { _ in
        s.transferUserInfo(msg)
        promise.resolve("queued")
      })
    } else {
      s.transferUserInfo(msg)
      promise.resolve("queued")
    }
  }

  private func forward(_ msg: [String: Any]) {
    guard msg["type"] as? String == "pairStatus" else { return }
    var body: [String: Any] = ["type": "pairStatus"]
    for k in ["status", "fingerprint", "host", "error"] {
      if let v = msg[k] as? String { body[k] = v }
    }
    emit(body)
  }

  // MARK: WCSessionDelegate

  func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: Error?) {
    emit(["type": "state"])
  }

  func sessionDidBecomeInactive(_ session: WCSession) {}

  // The user switched to another watch: activate again for the new one.
  func sessionDidDeactivate(_ session: WCSession) {
    WCSession.default.activate()
  }

  func sessionWatchStateDidChange(_ session: WCSession) {
    emit(["type": "state"])
  }

  func sessionReachabilityDidChange(_ session: WCSession) {
    emit(["type": "state"])
  }

  func session(_ session: WCSession, didReceiveMessage message: [String: Any]) {
    forward(message)
  }

  func session(_ session: WCSession, didReceiveMessage message: [String: Any], replyHandler: @escaping ([String: Any]) -> Void) {
    forward(message)
    replyHandler(["ok": true])
  }

  func session(_ session: WCSession, didReceiveUserInfo userInfo: [String: Any] = [:]) {
    forward(userInfo)
  }
}
