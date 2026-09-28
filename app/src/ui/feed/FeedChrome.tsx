// SPDX-License-Identifier: GPL-3.0-or-later
// Feed chrome that is not a card: the snackbar, missed requests, requests this app cannot show.
import { useEffect, useRef } from "react";
import { Animated, Pressable, Text, View } from "react-native";
import { formatHhmm } from "../components";
import { usePalette } from "../theme";
import { useT } from "../i18n";
import { setState, useAppState } from "../../core/store";
import { dismissMissed } from "../../core/missed";
import { sanitizeText } from "../../core/display";
import { styles } from "./styles";
import { SNACK_DURATION_MS } from "./timing";

// ---------------------------------------------------------------------------
// Snackbar after a decision
// ---------------------------------------------------------------------------
export function Snackbar() {
  const p = usePalette();
  const t = useT();
  const snack = useAppState((s) => s.snack);
  const anim = useRef(new Animated.Value(0)).current;
  useEffect(() => {
    if (!snack) return;
    anim.setValue(0);
    Animated.timing(anim, { toValue: 1, duration: 180, useNativeDriver: true }).start();
    const tm = setTimeout(() => {
      Animated.timing(anim, { toValue: 0, duration: 200, useNativeDriver: true }).start(() => setState((s) => (s.snack?.id === snack.id ? { snack: null } : {})));
    }, SNACK_DURATION_MS);
    return () => clearTimeout(tm);
  }, [snack?.id, anim]);
  if (!snack) return null;
  const color = snack.tone === "allow" ? p.allow : snack.tone === "deny" ? p.deny : p.muted;
  // The snackbar catches touches itself (ux-visual V-22): with pointerEvents="none" a touch on it went
  // to the button underneath, and an attempt to swipe the snackbar away allowed an ordinary card with
  // one touch. A touch on the snackbar only closes it.
  const close = () => setState((s) => (s.snack?.id === snack.id ? { snack: null } : {}));
  return (
    <Animated.View
      pointerEvents="auto"
      style={[styles.snack, { backgroundColor: p.card, borderColor: color, opacity: anim, transform: [{ translateY: anim.interpolate({ inputRange: [0, 1], outputRange: [20, 0] }) }] }]}
      accessibilityLiveRegion="polite"
      testID="snackbar"
    >
      <Pressable onPress={close} accessibilityRole="button" accessibilityHint={t("feed.snack.closeHint")} style={styles.snackInner}>
        <Text style={{ color: p.text, fontSize: 14 }} numberOfLines={2}>
          {snack.text}
        </Text>
      </Pressable>
    </Animated.View>
  );
}

/**
 * Requests with an envelope of an unknown version (newer than the app): how many and what to update.
 * No buttons: the phone cannot parse and recompute such an envelope, the request expires on the
 * server (fail-closed).
 */
export function UnshownBlock() {
  const p = usePalette();
  const t = useT();
  const n = useAppState((s) => s.unshown.length);
  if (!n) return null;
  return (
    <View style={[styles.missed, { borderColor: p.warn, backgroundColor: p.card }]} testID="unshown-block" accessible>
      <Text style={{ color: p.text, fontSize: 15, fontWeight: "700", marginBottom: 4 }} accessibilityRole="header">
        {t("feed.unshown.title", { n })}
      </Text>
      <Text style={{ color: p.muted, fontSize: 12 }}>{t("feed.unshown.hint")}</Text>
    </View>
  );
}

/** "Missed (N)": requests whose time ran out without a decision; stays until the human hides it. */
export function MissedBlock() {
  const p = usePalette();
  const t = useT();
  const missed = useAppState((s) => s.missed);
  if (!missed.length) return null;
  return (
    <View style={[styles.missed, { borderColor: p.border, backgroundColor: p.card }]} testID="missed-block">
      <View style={styles.row}>
        <Text style={{ color: p.text, fontSize: 15, fontWeight: "700" }} accessibilityRole="header">
          {t("feed.missed.title", { n: missed.length })}
        </Text>
        <Pressable onPress={dismissMissed} accessibilityRole="button" hitSlop={10} testID="missed-dismiss">
          <Text style={{ color: p.accent, fontWeight: "600" }}>{t("feed.missed.dismiss")}</Text>
        </Pressable>
      </View>
      <Text style={{ color: p.muted, fontSize: 12, marginBottom: 4 }}>{t("feed.missed.hint")}</Text>
      {missed.slice(0, 5).map((m) => (
        <View key={m.id} style={{ paddingVertical: 4 }}>
          <Text style={{ color: p.muted, fontSize: 12 }}>{t("feed.missed.item", { time: formatHhmm(m.expiredAt), host: m.host ?? "?" })}</Text>
          <Text style={{ color: p.text, fontSize: 14 }} numberOfLines={2}>
            {sanitizeText(m.summary)}
          </Text>
        </View>
      ))}
    </View>
  );
}
