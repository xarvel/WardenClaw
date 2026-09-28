// SPDX-License-Identifier: GPL-3.0-or-later
// Notifications for the iPhone itself. iOS does not allow our own connection in the background, so
// wardend sends an APNs push when a card appears (daemon/push.go; protocol/README.md, section 8).
// Here: permission (our own explanation first, then the iOS dialog), the APNs token from iOS,
// registering the token with wardend via a signed request (/v1/push/register, topic = bundle id,
// com.wardenclaw.app) and unregistering it when turned off. The push carries only the card id:
// the command, host and paths do not go through Apple, and the lock screen shows
// "Approval request · Open to review". The time-sensitive level breaks through Focus.
// The notification has no actions (modules/wardenpush): a tap opens the card, approving happens
// only in the app after Face ID or the passcode.
import { errMsg } from "./errMsg";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { Alert, AppState, Platform } from "react-native";
import { onOpenCard, push } from "../../modules/wardenpush";
import { wardendPushRegister, wardendPushUnregister } from "./controller";
import { t } from "./i18n";
import { loadNotifAsked, saveNotifAsked } from "./settings";
import { getState, pushLog, setState, subscribe, type PushStatus } from "./store";
import { WardendHttpError } from "./wardendClient";

const K_PUSH = "wc.push.ios.v1"; // what is already registered: {token, environment, topic, supervisorId}

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
  if (Platform.OS !== "ios" || !push || inited) return;
  inited = true;
  setState((s) => ({ bg: { ...s.bg, supported: true } }));
  const first = push.takeLaunchCardId();
  if (first) openCard(first);
  onOpenCard(() => {
    const id = push?.takeLaunchCardId();
    if (id) openCard(id);
  });
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
      const msg = e instanceof WardendHttpError ? e.reason : errMsg(e);
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

/** Our own explanation before the iOS dialog: once on its own (after pairing), always from the toggle. */
async function explain(explicit: boolean): Promise<boolean> {
  if (explicit) return true;
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
  const saved = await loadSaved();
  const paired = s.wardend.status === "connected" || s.wardend.status === "unavailable";
  if (!s.bgNotify || !paired) {
    if (saved && s.bgNotify === false && s.wardend.status === "connected" && s.wardend.supervisorId === saved.supervisorId) {
      // Notifications turned off: remove the token from the server so it does not push in vain
      await wardendPushUnregister(saved.token);
      await AsyncStorage.removeItem(K_PUSH);
    } else if (saved && !paired) {
      // Server forgotten or unpaired: `wardend pair revoke` removes the token, here just forget it
      await AsyncStorage.removeItem(K_PUSH);
    }
    setPush("off");
    return;
  }
  let perm = await native.getPermission();
  if (perm.status === "notDetermined") {
    if (!(await explain(explicit))) {
      setPush("off");
      return;
    }
    perm = await native.requestPermission();
  }
  setState((st) => ({
    bg: {
      ...st.bg,
      permission: perm.status === "denied" ? "denied" : perm.status === "notDetermined" ? "unknown" : "granted",
      timeSensitive: perm.timeSensitive === "enabled" ? true : perm.timeSensitive === "disabled" ? false : null,
    },
  }));
  if (perm.status === "denied" || perm.status === "notDetermined") {
    setPush("no-permission");
    return;
  }
  if (s.wardend.status !== "connected") {
    // No connection to the server: register once it is back (wardend itself checks the signature)
    if (saved?.supervisorId === s.wardend.supervisorId) setPush("registered");
    return;
  }
  const reg = await native.register();
  if (saved && saved.token === reg.token && saved.environment === reg.environment && saved.topic === reg.topic && saved.supervisorId === s.wardend.supervisorId) {
    setPush("registered");
    return;
  }
  setPush("registering");
  try {
    const supervisorId = await wardendPushRegister(reg.token, reg.topic, reg.environment);
    await AsyncStorage.setItem(K_PUSH, JSON.stringify({ ...reg, supervisorId } satisfies Saved));
    setPush("registered");
    pushLog(`push: APNs token registered with wardend (${reg.environment}, ${reg.topic})`);
  } catch (e) {
    if (e instanceof WardendHttpError && e.reason === "push_not_configured") {
      setPush("not-configured");
      return;
    }
    throw e;
  }
}
