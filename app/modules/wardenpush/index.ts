// SPDX-License-Identifier: GPL-3.0-or-later
// Notifications for the iPhone itself via APNs: wardend sends a push with the card id, the app
// fetches the card itself over the signed channel. Registration logic is in src/core/phonePush.ts.
import Native from "./src/WardenPushModule";

export type { PushPermission, PushRegistration, PushSetting } from "./src/WardenPushModule";
export const push = Native;

/** Notification tapped while the app is running: the card id. */
export function onOpenCard(listener: (cardId: string) => void): () => void {
  const sub = Native?.addListener?.("onOpenCard", (e) => listener(e.cardId));
  return () => sub?.remove();
}
