// SPDX-License-Identifier: GPL-3.0-or-later
// Bench build: block at the bottom of the "Mode" screen. Entry to the judge benchmark and the screen
// protection switch for documentation screenshots. Release builds do not contain this code
// (src/bench/entry.ts).
import React from "react";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { Platform, Pressable, StyleSheet, Switch, Text, View } from "react-native";
import { watch } from "../../modules/wardenwatch";
import { setState, useAppState } from "../core/store";
import { Section } from "../ui/components";
import { useT } from "../ui/i18n";
import { usePalette } from "../ui/theme";
import { setBenchOpen } from "./runner";

const K_SCREEN_OFF = "wc.bench.screen_protect_off.v1";

/** Android: FLAG_SECURE (the native part clears it only in bench and remembers the choice until MainActivity.onCreate); iOS: PrivacyShield overlay. */
export function setScreenProtect(on: boolean) {
  watch?.setScreenSecure?.(on);
  setState({ screenProtect: on });
  AsyncStorage.setItem(K_SCREEN_OFF, on ? "0" : "1").catch(() => {});
}

/** On startup: restore the switch to its previous position (protection is on by default). */
export async function initBenchScreen() {
  if ((await AsyncStorage.getItem(K_SCREEN_OFF)) === "1") setScreenProtect(false);
}

export function BenchSection() {
  const p = usePalette();
  const t = useT();
  const protect = useAppState((s) => s.screenProtect);
  return (
    <Section title="Bench">
      <View style={styles.row}>
        <View style={{ flex: 1 }}>
          <Text style={{ color: p.text, fontSize: 15, fontWeight: "600" }}>{t("screen.protect")}</Text>
          <Text style={{ color: p.muted, fontSize: 12, marginTop: 2 }}>{t("screen.protectHint")}</Text>
        </View>
        <Switch value={protect} onValueChange={setScreenProtect} accessibilityLabel={t("screen.protect")} testID="bench-screen-protect" />
      </View>
      {Platform.OS === "android" || Platform.OS === "ios" ? (
        <Pressable onPress={() => setBenchOpen(true)} style={{ alignSelf: "center", marginTop: 16, padding: 8 }} testID="bench-entry">
          <Text style={{ color: p.accent, fontSize: 13 }}>{t("bench.entry")}</Text>
        </Pressable>
      ) : null}
    </Section>
  );
}

const styles = StyleSheet.create({
  row: { flexDirection: "row", alignItems: "center", gap: 12 },
});
