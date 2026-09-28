// SPDX-License-Identifier: GPL-3.0-or-later
// "Apple Watch" section on the Mode tab (iOS only). The watch is a separate trusted wardend device
// with its own key in the Secure Enclave; the phone only passes it the pairing link (the watch has
// no camera): we scan the QR of a new link (`wardend pair start` on the server) or paste it from the
// clipboard, check it and send it via WatchConnectivity. A link cannot be used twice: the watch
// needs a new one, not the one the phone was paired with.
import { useEffect, useState } from "react";
import { Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import * as Clipboard from "expo-clipboard";
import { fonts, usePalette } from "./theme";
import { BigButton, Section } from "./components";
import { QrScannerModal } from "./QrScanner";
import { useT } from "./i18n";
import { parsePairLink } from "../core/wardendProto";
import { onWatchStatus, sendPairingLinkToWatch, watchLinkStatus, WatchLinkStatus } from "../../modules/applewatch";
import { errMsg } from "../core/errMsg";
import { tOr } from "../core/i18n";

type Report = { status: string; fingerprint?: string; host?: string; error?: string };

export function AppleWatchSection() {
  const p = usePalette();
  const t = useT();
  const [st, setSt] = useState<WatchLinkStatus | null>(() => watchLinkStatus());
  const [scan, setScan] = useState(false);
  const [name, setName] = useState("Apple Watch");
  const [msg, setMsg] = useState<{ text: string; bad: boolean } | null>(null);
  const [report, setReport] = useState<Report | null>(null);

  useEffect(
    () =>
      onWatchStatus((e) => {
        setSt(watchLinkStatus());
        if (e.type === "pairStatus") setReport({ status: e.status, fingerprint: e.fingerprint, host: e.host, error: e.error });
      }),
    [],
  );

  const send = async (text: string) => {
    setMsg(null);
    setReport(null);
    let host = "";
    try {
      host = parsePairLink(text).host;
    } catch (e) {
      return setMsg({ text: errMsg(e), bad: true });
    }
    try {
      const r = await sendPairingLinkToWatch(text.trim(), name.trim() || "Apple Watch");
      setMsg({ text: t(r === "delivered" ? "aw.delivered" : "aw.queued", { host: host || "wardend" }), bad: false });
    } catch (e) {
      const code = String((e as { code?: string })?.code ?? "");
      setMsg({ text: tOr(`aw.err.${code}`, errMsg(e)), bad: true });
    }
    setSt(watchLinkStatus());
  };

  const paste = async () => {
    const s = await Clipboard.getStringAsync();
    if (s) send(s);
  };

  const state = !st ? t("aw.noModule") : !st.supported ? t("aw.unsupported") : !st.paired ? t("aw.notPaired") : !st.installed ? t("aw.notInstalled") : st.reachable ? t("aw.ready") : t("aw.readyClosed");
  const canSend = !!st && st.supported && st.paired && st.installed;

  return (
    <Section title={t("aw.section")}>
      <Text style={{ color: p.text, fontSize: 14 }}>{t("aw.intro")}</Text>
      <Text style={{ color: canSend ? p.muted : p.warn, fontSize: 13, marginTop: 8 }}>{state}</Text>
      <Text style={[styles.label, { color: p.muted }]}>{t("aw.name")}</Text>
      <TextInput value={name} onChangeText={setName} maxLength={64} style={[styles.input, { color: p.text, backgroundColor: p.input, borderColor: p.border }]} />
      <Text style={{ color: p.muted, fontSize: 12, marginTop: 8 }}>{t("aw.newLinkHint")}</Text>
      <View style={styles.row}>
        <BigButton title={t("aw.scan")} color={p.accent} textColor={p.accentText} disabled={!canSend} onPress={() => setScan(true)} />
        <Pressable onPress={paste} disabled={!canSend} style={[styles.smallBtn, { borderColor: p.border, opacity: canSend ? 1 : 0.5 }]}>
          <Text style={{ color: p.accent, fontWeight: "600" }}>{t("aw.paste")}</Text>
        </Pressable>
      </View>
      {msg ? <Text style={{ color: msg.bad ? p.deny : p.text, fontSize: 13, marginTop: 8 }}>{msg.text}</Text> : null}
      {report ? (
        <View style={{ marginTop: 8 }}>
          {report.status === "error" ? (
            <Text style={{ color: p.deny, fontSize: 13 }}>{t("aw.watchError", { error: report.error ?? "?" })}</Text>
          ) : report.status === "approved" ? (
            <Text style={{ color: p.text, fontSize: 13 }}>{t("aw.approved", { host: report.host ?? "wardend" })}</Text>
          ) : report.status === "pending" ? (
            <>
              <Text style={{ color: p.text, fontSize: 13 }}>{t("aw.pending")}</Text>
              {report.fingerprint ? <Text style={{ color: p.text, fontSize: 16, fontFamily: fonts.mono, marginTop: 4 }}>{report.fingerprint}</Text> : null}
            </>
          ) : (
            <Text style={{ color: p.warn, fontSize: 13 }}>{t("aw.other", { status: report.status })}</Text>
          )}
        </View>
      ) : null}
      <QrScannerModal
        visible={scan}
        onClose={() => setScan(false)}
        onScanned={(text) => {
          setScan(false);
          send(text);
        }}
      />
    </Section>
  );
}

const styles = StyleSheet.create({
  label: { fontSize: 12, marginTop: 10, marginBottom: 4 },
  input: { borderWidth: 1, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 8, fontSize: 15 },
  row: { flexDirection: "row", gap: 10, alignItems: "center", marginTop: 10 },
  smallBtn: { borderWidth: 1, borderRadius: 8, paddingHorizontal: 12, paddingVertical: 10 },
});
