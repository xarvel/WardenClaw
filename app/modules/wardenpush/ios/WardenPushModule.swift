// SPDX-License-Identifier: GPL-3.0-or-later
// Notifications for the iPhone itself. iOS does not let an app keep its own connection in the
// background, so wardend sends an APNs push when a card appears (daemon/push.go, apns.go;
// protocol/README.md, section 8). This module only does the phone side:
//
//   getPermission() / requestPermission()  → {status, timeSensitive, lockScreen, alert}
//   register()                             → {token, environment, topic}; the app signs it to /v1/push/register
//   takeLaunchCardId()                     → the card of the notification the user tapped (cold or warm start)
//   clearDelivered(cardId | null)          → remove delivered notifications of a card (null: all of them)
//   event onOpenCard {cardId}              ← a tap on a notification while the app is running
//
// The payload carries only the card id; command, host and paths never go through Apple. The
// server marks the push time-sensitive, so it shows on the lock screen and breaks through Focus
// (entitlement com.apple.developer.usernotifications.time-sensitive). The category
// WARDEN_APPROVAL has no actions at all: nothing is approved from a notification, a tap opens the
// app, and the app approves only after Face ID or the passcode.
import ExpoModulesCore
import UIKit
import UserNotifications

public class WardenPushModule: Module {
  public func definition() -> ModuleDefinition {
    Name("WardenPush")

    Events("onOpenCard")

    OnCreate {
      PushCenter.shared.onOpenCard = { [weak self] id in
        self?.sendEvent("onOpenCard", ["cardId": id])
      }
    }

    OnDestroy {
      PushCenter.shared.onOpenCard = nil
    }

    AsyncFunction("getPermission") { (promise: Promise) in
      PushCenter.shared.settings { promise.resolve($0) }
    }

    AsyncFunction("requestPermission") { (promise: Promise) in
      UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, error in
        if let error = error {
          promise.reject("PERMISSION", error.localizedDescription)
          return
        }
        PushCenter.shared.settings { promise.resolve($0) }
      }
    }

    AsyncFunction("register") { (promise: Promise) in
      PushCenter.shared.register(promise)
    }

    Function("takeLaunchCardId") { () -> String? in
      PushCenter.shared.takePendingCardId()
    }

    Function("clearDelivered") { (cardId: String?) in
      PushCenter.shared.clearDelivered(cardId)
    }

    // Not about push: the app journal (expo-sqlite, Documents/SQLite) must stay on this phone,
    // and Documents goes to the iCloud backup by default (app/docs/app-hardening.md). On the
    // directory the attribute covers the database with its -wal and -shm files; the journal sets
    // it at every start, because a restore or a move to another phone can drop it.
    Function("excludeFromBackup") { (path: String) -> Bool in
      var url = URL(fileURLWithPath: path, isDirectory: true)
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      do {
        try url.setResourceValues(values)
        return true
      } catch {
        return false
      }
    }
  }
}

/// The earliest hooks: the notification delegate must be set before launch finishes, otherwise a
/// tap that launched the app is lost.
public class WardenPushAppDelegate: ExpoAppDelegateSubscriber {
  public func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
    PushCenter.shared.install()
    return true
  }

  public func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
    PushCenter.shared.didRegister(deviceToken)
  }

  public func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
    PushCenter.shared.didFail(error)
  }
}

final class PushCenter: NSObject, UNUserNotificationCenterDelegate {
  static let shared = PushCenter()
  /// The category wardend puts into every push (apnsCategory in daemon/apns.go).
  static let category = "WARDEN_APPROVAL"

  private let lock = NSLock()
  private var pendingCardId: String?
  private var waiters: [Int: Promise] = [:]
  private var nextWaiter = 0
  var onOpenCard: ((String) -> Void)?

  func install() {
    let center = UNUserNotificationCenter.current()
    center.delegate = self
    // No actions: no "Approve", and no "Deny" either. A tap opens the card in the app.
    let cat = UNNotificationCategory(identifier: PushCenter.category, actions: [], intentIdentifiers: [], options: [])
    center.setNotificationCategories([cat])
  }

  func settings(_ done: @escaping ([String: Any]) -> Void) {
    UNUserNotificationCenter.current().getNotificationSettings { s in
      done([
        "status": PushCenter.name(s.authorizationStatus),
        "timeSensitive": PushCenter.name(s.timeSensitiveSetting),
        "lockScreen": PushCenter.name(s.lockScreenSetting),
        "alert": PushCenter.name(s.alertSetting),
      ])
    }
  }

  static func name(_ s: UNAuthorizationStatus) -> String {
    switch s {
    case .authorized: return "granted"
    case .denied: return "denied"
    case .notDetermined: return "notDetermined"
    case .provisional: return "provisional"
    case .ephemeral: return "ephemeral"
    @unknown default: return "unknown"
    }
  }

  static func name(_ s: UNNotificationSetting) -> String {
    switch s {
    case .enabled: return "enabled"
    case .disabled: return "disabled"
    case .notSupported: return "notSupported"
    @unknown default: return "unknown"
    }
  }

  // MARK: APNs token

  func register(_ promise: Promise) {
    lock.lock()
    let id = nextWaiter
    nextWaiter += 1
    waiters[id] = promise
    lock.unlock()
    DispatchQueue.main.async {
      UIApplication.shared.registerForRemoteNotifications()
    }
    // iOS answers in a second or two; without a network it may stay silent. Do not hang forever.
    DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
      guard let self = self else { return }
      self.lock.lock()
      let p = self.waiters.removeValue(forKey: id)
      self.lock.unlock()
      p?.reject("TIMEOUT", "iOS did not return an APNs token in 30 s")
    }
  }

  func didRegister(_ deviceToken: Data) {
    let token = deviceToken.map { String(format: "%02x", $0) }.joined()
    let body: [String: Any] = [
      "token": token,
      "environment": PushEnvironment.current,
      "topic": Bundle.main.bundleIdentifier ?? "com.wardenclaw.app",
    ]
    for p in takeWaiters() { p.resolve(body) }
  }

  func didFail(_ error: Error) {
    for p in takeWaiters() { p.reject("REGISTER", error.localizedDescription) }
  }

  private func takeWaiters() -> [Promise] {
    lock.lock()
    defer { lock.unlock() }
    let list = Array(waiters.values)
    waiters.removeAll()
    return list
  }

  // MARK: taps and cleanup

  func takePendingCardId() -> String? {
    lock.lock()
    defer { lock.unlock() }
    let id = pendingCardId
    pendingCardId = nil
    return id
  }

  func clearDelivered(_ cardId: String?) {
    let center = UNUserNotificationCenter.current()
    center.getDeliveredNotifications { list in
      let ids = list.filter { n in
        let info = n.request.content.userInfo
        guard n.request.content.categoryIdentifier == PushCenter.category || info["cardId"] != nil else { return false }
        return cardId == nil || (info["cardId"] as? String) == cardId
      }.map { $0.request.identifier }
      if !ids.isEmpty { center.removeDeliveredNotifications(withIdentifiers: ids) }
    }
  }

  // The app is open: the card is already in the feed (long poll), keep only the entry in the list.
  func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                              withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
    completionHandler([.list])
  }

  // A tap (after Face ID or the passcode if the phone was locked): open the card.
  func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                              withCompletionHandler completionHandler: @escaping () -> Void) {
    if let id = response.notification.request.content.userInfo["cardId"] as? String {
      lock.lock()
      pendingCardId = id
      let cb = onOpenCard
      lock.unlock()
      DispatchQueue.main.async { cb?(id) }
    }
    completionHandler()
  }
}

/// Which APNs environment this build's token belongs to: builds signed with a development profile
/// get sandbox tokens, ad hoc, TestFlight and App Store builds production ones. The embedded
/// profile (present in development and ad hoc builds) says which; App Store builds have none.
/// Same rule as the watch app (targets/watch/App/WatchModel.swift).
enum PushEnvironment {
  static var current: String {
    #if targetEnvironment(simulator)
    return "sandbox"
    #else
    guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
          let data = try? Data(contentsOf: url),
          let text = String(data: data, encoding: .isoLatin1) else { return "production" }
    guard let r = text.range(of: "<key>aps-environment</key>") else { return "production" }
    let tail = text[r.upperBound...].prefix(80)
    return tail.contains("development") ? "sandbox" : "production"
    #endif
  }
}
