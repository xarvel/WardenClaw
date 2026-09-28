// SPDX-License-Identifier: GPL-3.0-or-later
// WardenClaw for Apple Watch: an independent watchOS app with its own Secure Enclave key and its
// own device record in wardend. Approve only inside the app (hold the button or turn the Digital
// Crown to the end); the notification offers only Deny and Open.
//
// Why no "Approve" in the notification: on Series 9 / Ultra 2 the double tap gesture presses the
// first action of a notification. An approval must never be one accidental pinch away, so the
// category WARDEN_APPROVAL has "Open" first (harmless) and "Deny" (destructive) second, and
// nothing in the app carries .handGestureShortcut(.primaryAction) on an approve control.
//
// Push payload from wardend: {"aps":{…,"category":"WARDEN_APPROVAL"},"cardId":"<id>"}; command
// details never travel through APNs, the watch fetches the card from wardend and checks it.
import SwiftUI
import UserNotifications
import WatchKit

@main
struct WardenWatchApp: App {
  @WKApplicationDelegateAdaptor(AppDelegate.self) private var delegate
  @StateObject private var model = WatchModel.shared
  @Environment(\.scenePhase) private var scenePhase

  var body: some Scene {
    WindowGroup {
      RootView()
        .environmentObject(model)
    }
    .onChange(of: scenePhase) { _, phase in
      model.setActive(phase == .active)
    }
  }
}

enum NotificationIds {
  static let open = "WARDEN_OPEN"
  static let deny = "WARDEN_DENY"

  static func registerCategory() {
    let open = UNNotificationAction(identifier: open, title: L.t("Open"), options: [.foreground])
    let deny = UNNotificationAction(identifier: deny, title: L.t("Deny"), options: [.destructive])
    // Order matters: the double tap takes the first action. It must be "Open", never an approval.
    let cat = UNNotificationCategory(identifier: WatchPush.category, actions: [open, deny], intentIdentifiers: [], options: [])
    UNUserNotificationCenter.current().setNotificationCategories([cat])
  }
}

final class AppDelegate: NSObject, WKApplicationDelegate, UNUserNotificationCenterDelegate {
  func applicationDidFinishLaunching() {
    let center = UNUserNotificationCenter.current()
    center.delegate = self
    NotificationIds.registerCategory()
    center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
    PhoneLink.shared.activate()
    Task { @MainActor in WatchModel.shared.start() }
  }

  func didRegisterForRemoteNotifications(withDeviceToken deviceToken: Data) {
    Task { @MainActor in WatchModel.shared.didRegister(deviceToken: deviceToken) }
  }

  func didFailToRegisterForRemoteNotificationsWithError(_ error: Error) {
    Task { @MainActor in WatchModel.shared.lastError = L.t("Push unavailable: ") + error.localizedDescription }
  }

  // A push while the app is open: show it and refresh the list.
  func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                              withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
    Task { @MainActor in _ = await WatchModel.shared.refresh() }
    completionHandler([.banner, .sound])
  }

  func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                              withCompletionHandler completionHandler: @escaping () -> Void) {
    let cardId = response.notification.request.content.userInfo["cardId"] as? String
    switch response.actionIdentifier {
    case NotificationIds.deny:
      // Runs in the background: fetch the record, sign deny with the watch key, then finish.
      guard let id = cardId else { return completionHandler() }
      Task { @MainActor in
        await WatchModel.shared.denyFromNotification(cardId: id)
        completionHandler()
      }
    default:
      // "Open" or a tap on the notification: open the card (approval happens only in the app).
      Task { @MainActor in
        WatchModel.shared.openCardId = cardId
        _ = await WatchModel.shared.refresh()
        completionHandler()
      }
    }
  }
}
