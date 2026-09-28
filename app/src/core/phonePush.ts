// SPDX-License-Identifier: GPL-3.0-or-later
// Notifications for the phone itself. iOS does not allow our own connection in the background and
// Android may stop the background service, so the relay sends a push (APNs, FCM) when a frame for
// this phone arrives and the phone has no live connection (protocol/README.md, section 8). Here:
// permission (on iOS our own explanation first, then the system dialog), the token from the
// system, registering the token with the relay over the session (push.register, topic = bundle
// id / package name, com.wardenclaw.app) and unregistering it when turned off. The push carries
// the boxed frame, which neither the relay nor Apple or Google can open: the lock screen shows
// "Approval request · Open to review". On iOS the time-sensitive level breaks through Focus.
// The notification has no actions (modules/wardenpush): a tap opens the app, approving happens
// only there after the owner check.
import { errMsg } from "./errMsg";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { Alert, AppState, Platform } from "react-native";
import { onOpenCard, onPushToken, push } from "../../modules/wardenpush";
import { setPushTokenSource, wardendPushRegister, wardendPushUnregister } from "./wardendSession";
import { t } from "./i18n";
import { loadNotifAsked, saveNotifAsked } from "./settings";
import { getState, pushLog, setState, subscribe, type PushStatus } from "./store";

const K_PUSH = "wc.push.v1"; // what is already registered: {token, environment, topic, supervisorId}
const IOS = Platform.OS === "ios";
const PLATFORM = IOS ? ("apns" as const) : ("fcm" as const);
const SERVICE = IOS ? "APNs" : "FCM";

type Saved = { token: string; environment: string; topic: string; supervisorId: string };

let inited = false;
let busy = false;
let again = false;
let againExplicit = false;
let asking = false;

function setPush(state: PushStatus["state"], detail: string | null = null) {
  setState((s) => (s.bg.push.state === state && s.bg.push.detail === detail ? {} : { bg: { ...s.bg, push: { state, detail } } }));
}

async function loadSaved(): Promise<Saved | null> {
  try {
    const raw = await AsyncStorage.getItem(K_PUSH);
    return raw ? (JSON.parse(raw) as Saved) : null;
  } catch {
    return null;
  }
}

/** Idempotent; App calls it after bootstrap. openCard: a notification was tapped (cold or warm start). */
export function initPhonePush(openCard: (id: string) => void) {
  if ((!IOS && Platform.OS !== "android") || !push || inited) return;
  inited = true;
  setPushTokenSource(async () => {
    const saved = await loadSaved();
    return saved ? { platform: PLATFORM, token: saved.token } : null;
  });
  if (IOS) {
    // on Android "supported" is the background service (background.ts), and a tap arrives as a link (App.tsx)
    setState((s) => ({ bg: { ...s.bg, supported: true } }));
    const first = push.takeLaunchCardId();
    if (first) openCard(first);
    onOpenCard(() => {
      const id = push?.takeLaunchCardId();
      if (id) openCard(id);
    });
  } else {
    onPushToken(() => syncPhonePush());
  }
  push.clearDelivered(null);
  let lastSig = "";
  subscribe(() => {
    const s = getState();
    const sig = [s.ready, s.bgNotify, s.wardend.status, s.wardend.supervisorId].join("|");
    if (sig === lastSig) return;
    lastSig = sig;
    syncPhonePush();
  });
  AppState.addEventListener("change", (st) => {
    if (st !== "active") return;
    // App opened: cards are visible in the feed, pushes in Notification Center are no longer needed
    push?.clearDelivered(null);
    syncPhonePush();
  });
  syncPhonePush();
}

/** Bring the registration in line with the "Background notifications" setting and the pairing state. */
export function syncPhonePush(explicit = false) {
  if (busy) {
    again = true;
    againExplicit ||= explicit;
    return;
  }
  busy = true;
  doSync(explicit)
    .catch((e) => {
      const msg = errMsg(e);
      pushLog(`push: ${msg}`);
      setPush("error", msg);
    })
    .finally(() => {
      busy = false;
      if (again) {
        const ex = againExplicit;
        again = false;
        againExplicit = false;
        syncPhonePush(ex);
      }
    });
}

/**
 * Our own explanation before the iOS dialog: once on its own (after pairing), always from the
 * toggle. Android asks only from the toggle: the dialog of the background service comes first.
 */
async function explain(explicit: boolean): Promise<boolean> {
  if (explicit) return true;
  if (!IOS) return false;
  if (asking || AppState.currentState !== "active" || (await loadNotifAsked())) return false;
  asking = true;
  await saveNotifAsked();
  try {
    return await new Promise<boolean>((resolve) =>
      Alert.alert(t("bg.permAsk.title"), t("bg.permAsk.body"), [
        { text: t("bg.permAsk.later"), style: "cancel", onPress: () => resolve(false) },
        { text: t("bg.permAsk.allow"), onPress: () => resolve(true) },
      ]),
    );
  } finally {
    asking = false;
  }
}

async function doSync(explicit: boolean) {
  const native = push;
  if (!native) return;
  const s = getState();
  if (!s.ready) return;
  if (native.available?.() === false) {
    setPush("not-in-build");
    return;
  }
  const saved = await loadSaved();
  // a paired server, whatever its connection is doing ("connecting" without a server id is a pairing attempt)
  const paired = s.wardend.status === "connected" || s.wardend.status === "unavailable" || (s.wardend.status === "connecting" && !!s.wardend.supervisorId);
  if (!s.bgNotify || !paired) {
    if (saved && s.bgNotify === false && s.wardend.status === "connected" && s.wardend.supervisorId === saved.supervisorId) {
      // Notifications turned off: remove the token from the relay so it does not push in vain
      await wardendPushUnregister({ platform: PLATFORM, token: saved.token });
      await AsyncStorage.removeItem(K_PUSH);
    } else if (saved && !paired) {
      // Server forgotten: forgetWardend took the token off the relay, here just forget it
      await AsyncStorage.removeItem(K_PUSH);
    }
    setPush("off");
    return;
  }
  let perm = await native.getPermission();
  if (perm.status === "notDetermined") {
    if (!(await explain(explicit))) {
      setPush(IOS ? "off" : "no-permission");
      return;
    }
    perm = await native.requestPermission();
  }
  if (IOS) {
    // on Android the permission state belongs to the background service (background.ts)
    setState((st) => ({
      bg: {
        ...st.bg,
        permission: perm.status === "denied" ? "denied" : perm.status === "notDetermined" ? "unknown" : "granted",
        timeSensitive: perm.timeSensitive === "enabled" ? true : perm.timeSensitive === "disabled" ? false : null,
      },
    }));
  }
  if (perm.status === "denied" || perm.status === "notDetermined") {
    setPush("no-permission");
    return;
  }
  if (s.wardend.status !== "connected") {
    // No connection to the server: register once it is back
    if (saved?.supervisorId === s.wardend.supervisorId) setPush("registered");
    return;
  }
  const reg = await native.register();
  if (saved && saved.token === reg.token && saved.environment === reg.environment && saved.topic === reg.topic && saved.supervisorId === s.wardend.supervisorId) {
    setPush("registered");
    return;
  }
  setPush("registering");
  const r = await wardendPushRegister({ platform: PLATFORM, token: reg.token, environment: reg.environment, topic: reg.topic });
  if (!r.configured) {
    // the relay has no credentials for this platform: it keeps the token and cannot push
    setPush("not-configured");
    return;
  }
  await AsyncStorage.setItem(K_PUSH, JSON.stringify({ ...reg, supervisorId: r.supervisorId } satisfies Saved));
  setPush("registered");
  pushLog(`push: ${SERVICE} token registered with the relay (${reg.environment}, ${reg.topic})`);
}
