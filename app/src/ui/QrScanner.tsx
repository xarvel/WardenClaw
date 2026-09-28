// SPDX-License-Identifier: GPL-3.0-or-later
// Pairing QR scanner (expo-camera). Returns the text of the first QR that looks like a
// wardenclaw://pair link.
import { useRef } from "react";
import { Modal, Pressable, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { CameraView, useCameraPermissions } from "expo-camera";
import { usePalette } from "./theme";
import { BigButton } from "./components";
import { useT } from "./i18n";

export function QrScannerModal({ visible, onClose, onScanned }: { visible: boolean; onClose: () => void; onScanned: (text: string) => void }) {
  const p = usePalette();
  const t = useT();
  const [perm, requestPerm] = useCameraPermissions();
  const done = useRef(false);
  if (visible === false) done.current = false;

  return (
    <Modal visible={visible} animationType="slide" onRequestClose={onClose}>
      <SafeAreaView style={[styles.screen, { backgroundColor: "#000" }]}>
        {!perm ? null : !perm.granted ? (
          <View style={[styles.center, { backgroundColor: p.bg }]}>
            <Text style={[styles.title, { color: p.text }]}>{t("qr.permTitle")}</Text>
            <Text style={{ color: p.muted, textAlign: "center", marginBottom: 16 }}>{t("qr.permBody")}</Text>
            {perm.canAskAgain ? <BigButton title={t("qr.allowCamera")} color={p.accent} textColor={p.accentText} onPress={requestPerm} style={{ flex: 0, alignSelf: "stretch" }} /> : <Text style={{ color: p.deny }}>{t("qr.denied")}</Text>}
          </View>
        ) : (
          <CameraView
            style={StyleSheet.absoluteFill}
            facing="back"
            barcodeScannerSettings={{ barcodeTypes: ["qr"] }}
            onBarcodeScanned={({ data }) => {
              if (done.current || !/^wardenclaw:\/\/pair/i.test(data ?? "")) return;
              done.current = true;
              onScanned(data);
            }}
          />
        )}
        {perm?.granted ? (
          <View style={styles.overlay} pointerEvents="none">
            <View style={styles.frame} />
            <Text style={styles.overlayText}>{t("qr.aim")}</Text>
          </View>
        ) : null}
        <Pressable onPress={onClose} style={[styles.close, { backgroundColor: p.card }]} accessibilityRole="button">
          <Text style={{ color: p.text, fontWeight: "700" }}>{t("common.cancel")}</Text>
        </Pressable>
      </SafeAreaView>
    </Modal>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1 },
  center: { flex: 1, alignItems: "center", justifyContent: "center", padding: 24 },
  title: { fontSize: 20, fontWeight: "700", marginBottom: 8 },
  overlay: { position: "absolute", top: 0, left: 0, right: 0, bottom: 0, alignItems: "center", justifyContent: "center", gap: 16 },
  frame: { width: 260, height: 260, borderWidth: 3, borderColor: "#fff", borderRadius: 18 },
  overlayText: { color: "#fff", fontSize: 15, fontWeight: "600", textAlign: "center", paddingHorizontal: 24 },
  close: { position: "absolute", bottom: 32, alignSelf: "center", paddingHorizontal: 28, paddingVertical: 14, borderRadius: 14 },
});
