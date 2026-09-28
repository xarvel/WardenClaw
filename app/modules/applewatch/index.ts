// SPDX-License-Identifier: GPL-3.0-or-later
// Apple Watch: pass the wardend pairing link to the watch (the watch has no camera). From there the
// watch does everything itself: its own key in the Secure Enclave, pairing with wardend as a
// separate device (alg es256), its own APNs token. The phone's key is not passed to the watch.
// Watch app: targets/watch.
import Native, { WatchLinkStatus, WatchStatusEvent } from "./src/AppleWatchModule";

export type { WatchLinkStatus, WatchStatusEvent };

export const appleWatchAvailable = () => Native !== null;

export function watchLinkStatus(): WatchLinkStatus | null {
  try {
    return Native ? Native.status() : null;
  } catch {
    return null;
  }
}

/** "delivered": the watch app is open and received the link; "queued": it gets it when it opens. */
export async function sendPairingLinkToWatch(link: string, name: string): Promise<"delivered" | "queued"> {
  if (!Native) throw Object.assign(new Error("NO_MODULE"), { code: "NO_MODULE" });
  return Native.sendPairingLink(link, name);
}

export function onWatchStatus(listener: (e: WatchStatusEvent) => void): () => void {
  const sub = Native?.addListener?.("onWatchStatus", listener);
  return () => sub?.remove();
}
