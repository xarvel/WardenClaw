// SPDX-License-Identifier: GPL-3.0-or-later
import React from "react";
import { Pressable, StyleSheet, Text, View, ViewStyle } from "react-native";
import { usePalette } from "./theme";
import { AppState, ConnStatus, WardendState, useAppState } from "../core/store";
import { t } from "../core/i18n";
import { linkFault, runAsks, runCopy, type LinkFault, type RunCopy } from "../core/serverMode";
import { useT } from "./i18n";

export function BigButton({ title, onPress, color, textColor, disabled, style }: { title: string; onPress?: () => void; color: string; textColor: string; disabled?: boolean; style?: ViewStyle }) {
  const p = usePalette();
  return (
    <Pressable
      onPress={onPress}
      disabled={disabled}
      style={({ pressed }) => [styles.bigBtn, { backgroundColor: disabled ? p.disabled : color, opacity: pressed ? 0.8 : 1 }, style]}
      accessibilityRole="button"
    >
      <Text style={[styles.bigBtnText, { color: disabled ? p.muted : textColor }]} numberOfLines={1} adjustsFontSizeToFit minimumFontScale={0.7}>
        {title}
      </Text>
    </Pressable>
  );
}

export function Badge({ text, bg, color }: { text: string; bg: string; color: string }) {
  return (
    <View style={[styles.badge, { backgroundColor: bg }]}>
      <Text style={[styles.badgeText, { color }]}>{text}</Text>
    </View>
  );
}

type Tone = "ok" | "warn" | "bad";

/** OpenClaw adapter status (gateway). */
export function statusLabel(status: ConnStatus): { text: string; tone: Tone } {
  switch (status) {
    case "off":
      return { text: t("conn.off"), tone: "warn" };
    case "connected":
      return { text: t("conn.connected"), tone: "ok" };
    case "connecting":
      return { text: t("conn.connecting"), tone: "warn" };
    case "reconnecting":
      return { text: t("conn.reconnecting"), tone: "warn" };
    case "pairing":
      return { text: t("conn.pairing"), tone: "warn" };
    case "auth-failed":
      return { text: t("conn.authFailed"), tone: "bad" };
    default:
      return { text: t("conn.unpaired"), tone: "bad" };
  }
}

const FAULT_PILL: Record<LinkFault, "wd.unavailable" | "wd.fault.revoked" | "wd.fault.offline" | "wd.fault.protocol"> = {
  down: "wd.unavailable",
  revoked: "wd.fault.revoked",
  offline: "wd.fault.offline",
  protocol: "wd.fault.protocol",
};

const MODE_PILL: Record<RunCopy, "wd.mode.observe" | "wd.mode.denylist" | "wd.mode.tripwire" | "wd.mode.root" | "wd.mode.ticket"> = {
  observe: "wd.mode.observe",
  denylist: "wd.mode.denylist",
  tripwire: "wd.mode.tripwire",
  root: "wd.mode.root",
  ticket: "wd.mode.ticket",
};

/** Status of the link to wardend. Connected names the server mode: observe does not ask. */
export function wardendLabel(w: WardendState): { text: string; tone: Tone } {
  switch (w.status) {
    case "connected": {
      const copy = runCopy(w.mode, w.policyMode);
      if (!copy) return { text: t("wd.connected"), tone: "ok" };
      return { text: t(MODE_PILL[copy]), tone: runAsks(copy) ? "ok" : "warn" };
    }
    case "connecting":
      return { text: t("wd.connecting"), tone: "warn" };
    case "awaiting-approval":
      return { text: t("wd.awaiting"), tone: "warn" };
    case "unavailable": {
      const fault = linkFault(w.status, w.lastReason) ?? "down";
      return { text: t(FAULT_PILL[fault]), tone: "bad" };
    }
    case "rejected":
      return { text: t("wd.rejected"), tone: "bad" };
    default:
      return { text: t("wd.unpaired"), tone: "bad" };
  }
}

/** Overall status for the header: wardend comes first; if it is absent but the adapter works, the adapter status. */
export function overallLabel(s: Pick<AppState, "wardend" | "status" | "openclawAdapter">): { text: string; tone: Tone } {
  const w = wardendLabel(s.wardend);
  if (s.wardend.status !== "unpaired" || !s.openclawAdapter) return w;
  return statusLabel(s.status);
}

export function StatusPill() {
  const p = usePalette();
  useT();
  const wardend = useAppState((s) => s.wardend);
  const status = useAppState((s) => s.status);
  const openclawAdapter = useAppState((s) => s.openclawAdapter);
  const { text, tone } = overallLabel({ wardend, status, openclawAdapter });
  const color = tone === "ok" ? p.ok : tone === "warn" ? p.warn : p.deny;
  return (
    <View style={styles.pill}>
      <View style={[styles.dot, { backgroundColor: color }]} />
      <Text style={{ color: p.muted, fontSize: 13 }}>{text}</Text>
    </View>
  );
}

export function Section({ title, children }: { title: string; children: React.ReactNode }) {
  const p = usePalette();
  return (
    <View style={[styles.section, { backgroundColor: p.card, borderColor: p.border }]}>
      <Text style={[styles.sectionTitle, { color: p.muted }]}>{title}</Text>
      {children}
    </View>
  );
}

/** HH:MM for a timestamp in milliseconds. */
export function formatHhmm(ms: number): string {
  const d = new Date(ms);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

export function formatTtl(expiresAtMs: number | null, now: number): string {
  if (!expiresAtMs) return "";
  const s = Math.max(0, Math.round((expiresAtMs - now) / 1000));
  return s >= 60 ? `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}` : t("fmt.seconds", { s });
}

export function formatTime(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getDate())}.${pad(d.getMonth() + 1)} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

const styles = StyleSheet.create({
  bigBtn: { flex: 1, paddingVertical: 16, paddingHorizontal: 12, borderRadius: 14, alignItems: "center", justifyContent: "center" },
  bigBtnText: { fontSize: 18, fontWeight: "700" },
  badge: { paddingHorizontal: 8, paddingVertical: 3, borderRadius: 6 },
  badgeText: { fontSize: 11, fontWeight: "700", letterSpacing: 0.5 },
  pill: { flexDirection: "row", alignItems: "center", gap: 6 },
  dot: { width: 9, height: 9, borderRadius: 5 },
  section: { borderRadius: 14, borderWidth: StyleSheet.hairlineWidth, padding: 14, marginBottom: 14 },
  sectionTitle: { fontSize: 12, fontWeight: "700", textTransform: "uppercase", letterSpacing: 0.8, marginBottom: 10 },
});
