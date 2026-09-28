// SPDX-License-Identifier: GPL-3.0-or-later
// Persistent elements above the tabs: the "Autopilot is on" banner (above the tab bar, on any
// screen) and the iOS privacy overlay (the app switcher snapshot is taken after inactive, so
// commands are hidden earlier). On Android FLAG_SECURE does the same.
import { useEffect, useState } from "react";
import { AppState, Platform, Pressable, StyleSheet, Text, View } from "react-native";
import Ionicons from "@expo/vector-icons/Ionicons";
import { setMode } from "../core/controller";
import { useAppState } from "../core/store";
import { useT } from "./i18n";
import { usePalette } from "./theme";
import { formatHhmm } from "./components";

/** Judge autopilot is on: visible on every tab, turned off with one tap. */
export function AutopilotBanner() {
  const p = usePalette();
  const t = useT();
  const mode = useAppState((s) => s.mode);
  const until = useAppState((s) => s.autopilotUntil);
  if (mode !== "delegate") return null;
  const time = until !== null ? formatHhmm(until) : "?";
  return (
    <View style={[styles.bar, { backgroundColor: p.riskMid }]} accessibilityRole="alert" accessibilityLabel={t("autopilot.bannerA11y", { time })} testID="autopilot-banner">
      <Ionicons name="flash" size={16} color={p.riskMidText} />
      <Text style={[styles.text, { color: p.riskMidText }]} numberOfLines={2}>
        {t("autopilot.banner", { time })}
      </Text>
      <Pressable onPress={() => setMode("manual", "stop").catch(() => {})} accessibilityRole="button" hitSlop={8} style={[styles.btn, { borderColor: p.riskMidText }]} testID="autopilot-off">
        <Text style={{ color: p.riskMidText, fontWeight: "700", fontSize: 13 }}>{t("autopilot.off")}</Text>
      </Pressable>
    </View>
  );
}

/** iOS: while the app is not active, a placeholder replaces the screen (App Switcher snapshot without commands). */
export function PrivacyShield() {
  const p = usePalette();
  const protect = useAppState((s) => s.screenProtect);
  const [hidden, setHidden] = useState(false);
  useEffect(() => {
    if (Platform.OS !== "ios") return;
    const sub = AppState.addEventListener("change", (st) => setHidden(st !== "active"));
    return () => sub.remove();
  }, []);
  if (Platform.OS !== "ios" || !protect || !hidden) return null;
  return (
    <View style={[StyleSheet.absoluteFill, styles.shield, { backgroundColor: p.bg }]} pointerEvents="none">
      <Ionicons name="shield-checkmark" size={56} color={p.muted} />
      <Text style={{ color: p.muted, fontSize: 17, fontWeight: "700", marginTop: 12 }}>WardenClaw</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  bar: { flexDirection: "row", alignItems: "center", gap: 8, paddingHorizontal: 14, paddingVertical: 8 },
  text: { flex: 1, fontSize: 14, fontWeight: "700" },
  btn: { borderWidth: 1, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 4 },
  shield: { alignItems: "center", justifyContent: "center", zIndex: 1000, elevation: 1000 },
});
