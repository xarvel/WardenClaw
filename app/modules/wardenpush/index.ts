// SPDX-License-Identifier: GPL-3.0-or-later
// Notifications for the phone itself via APNs (iOS) or FCM (Android): the relay sends a push when
// a card arrives and the phone has no live connection, the app gets the card over its session.
// Registration logic is in src/core/phonePush.ts.
import Native from "./src/WardenPushModule";

export type { PushPermission, PushRegistration, PushSetting } from "./src/WardenPushModule";
export const push = Native;

/** Notification tapped while the app is running: the card id. */
export function onOpenCard(listener: (cardId: string) => void): () => void {
  const sub = Native?.addListener?.("onOpenCard", (e) => listener(e.cardId));
  return () => sub?.remove();
}

/** Android: Firebase replaced the token; the new one has to be registered with the relay. */
export function onPushToken(listener: () => void): () => void {
  const sub = Native?.addListener?.("onToken", listener);
  return () => sub?.remove();
}
