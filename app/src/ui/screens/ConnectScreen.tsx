// SPDX-License-Identifier: GPL-3.0-or-later
// "Connect": pairing with wardend via QR.
import { useEffect, useState } from "react";
import { Alert, KeyboardAvoidingView, Platform, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import * as Clipboard from "expo-clipboard";
import { fonts, usePalette } from "../theme";
import { BigButton, Section, StatusPill, wardendLabel } from "../components";
import { QrScannerModal } from "../QrScanner";
import { setState, useAppState } from "../../core/store";
import { fingerprint } from "../../core/relayProto";
import { relayHost } from "../../core/wardendSession";
import { useT } from "../i18n";
import { t as tr } from "../../core/i18n";
import { pairWithWardend, forgetWardend, OwnerNotConfirmed } from "../../core/controller";
import { alertActionError } from "../ownerAlert";
import { errMsg } from "../../core/errMsg";
import { planPairLink } from "../../core/links";
import { explainError } from "../../core/netError";

export default function ConnectScreen() {
  const p = usePalette();
  const t = useT();
  return (
    <SafeAreaView style={[styles.screen, { backgroundColor: p.bg }]} edges={["top"]}>
      <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : undefined} style={{ flex: 1 }}>
        <ScrollView contentContainerStyle={{ padding: 16, paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
          <View style={styles.header}>
            <Text style={[styles.h1, { color: p.text }]}>{t("tab.connect")}</Text>
            <StatusPill />
          </View>
          <ServerSection />
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

function ServerSection() {
  const p = usePalette();
  const t = useT();
  const w = useAppState((s) => s.wardend);
  const deviceId = useAppState((s) => s.deviceId);
  const [scan, setScan] = useState(false);
  const [link, setLink] = useState("");
  const [name, setName] = useState(() => (Platform.OS === "android" ? t("connect.defaultNameAndroid") : t("connect.defaultName")));
  const [busy, setBusy] = useState(false);
  const label = wardendLabel(w);
  // Deep link: into the field, connecting via the "Connect" button (check the host in the link). With
  // a server connected there is no field: the link waits in incoming, above the server details there
  // is an explanation of what to do (planPairLink), and after "Forget" it is already in the field.
  const pendingLink = useAppState((s) => s.pendingPairLink);
  const [incoming, setIncoming] = useState<string | null>(null);
  useEffect(() => {
    if (!pendingLink) return;
    setLink(pendingLink);
    setIncoming(pendingLink);
    setState({ pendingPairLink: null });
  }, [pendingLink]);

  const identityError = useAppState((s) => s.identityError);
  // pairing only on a tap and with owner confirmation (controller.ts, requireOwner)
  const pair = async (text: string) => {
    setBusy(true);
    try {
      await pairWithWardend(text, name);
      setLink("");
      setIncoming(null);
    } catch (e) {
      if (e instanceof OwnerNotConfirmed) alertActionError(e);
      else Alert.alert(t("connect.failed"), errMsg(e));
    } finally {
      setBusy(false);
    }
  };
  const paste = async () => {
    const text = await Clipboard.getStringAsync();
    if (text) setLink(text.trim());
  };
  const confirmForget = () =>
    Alert.alert(t("connect.forget.title"), t("connect.forget.body"), [
      { text: t("common.cancel"), style: "cancel" },
      { text: t("connect.forget.btn"), style: "destructive", onPress: () => forgetWardend().catch(alertActionError) },
    ]);

  const paired = w.status === "connected" || w.status === "unavailable";
  const waiting = w.status === "awaiting-approval";
  const plan = incoming && (paired || waiting) ? planPairLink(incoming, w) : null;
  const dismissIncoming = () => {
    setIncoming(null);
    setLink("");
  };

  return (
    <Section title={t("connect.section")}>
      {identityError ? <Text style={{ color: p.deny, fontWeight: "700", marginBottom: 8 }}>{identityError}</Text> : null}
      {plan && plan.kind !== "fill" ? (
        <View style={[styles.notice, { borderColor: plan.kind === "same" ? p.border : p.warn, marginTop: 0, marginBottom: 12 }]} accessibilityLiveRegion="polite" testID="pair-link-notice">
          <Text style={{ color: p.text, fontWeight: "700", marginBottom: 6 }}>
            {plan.kind === "replace" ? t("connect.link.otherTitle", { host: plan.host }) : plan.kind === "same" ? t("connect.link.sameTitle") : t("connect.link.badTitle")}
          </Text>
          <Text style={{ color: p.text }}>{plan.kind === "replace" ? t("connect.link.otherBody", { host: plan.host, current: plan.current }) : plan.kind === "same" ? t("connect.link.sameBody", { host: plan.host }) : plan.error}</Text>
          <View style={[styles.rowBtns, { marginTop: 10, marginBottom: 0, flexWrap: "wrap" }]}>
            {plan.kind === "replace" ? (
              <Pressable onPress={confirmForget} style={[styles.smallBtn, { borderColor: p.deny }]} accessibilityRole="button" testID="pair-link-forget">
                <Text style={{ color: p.deny, fontWeight: "700" }}>{t("connect.link.forget", { current: plan.current })}</Text>
              </Pressable>
            ) : null}
            <Pressable onPress={dismissIncoming} style={[styles.smallBtn, { borderColor: p.border }]} accessibilityRole="button" testID="pair-link-dismiss">
              <Text style={{ color: p.accent, fontWeight: "600" }}>{t("connect.link.dismiss")}</Text>
            </Pressable>
          </View>
        </View>
      ) : null}
      {paired || waiting ? (
        <>
          <Row label={t("common.status")} value={`${label.text}${w.mode ? t("connect.modeSuffix", { mode: w.mode }) : ""}`} />
          <Row label={t("connect.server")} value={w.host || "—"} />
          <Row label={t("connect.relay")} value={relayHost(w.relay) || "—"} mono />
          <Row label={t("connect.serverKey")} value={w.supervisorId ? fingerprint(w.supervisorId) : "—"} mono />
          <Row label={t("connect.thisPhone")} value={deviceId ? fingerprint(deviceId) : "—"} mono />
          {paired ? <Row label={t("connect.signed")} value={String(w.signed)} /> : null}
        </>
      ) : null}
      {waiting ? (
        <View style={[styles.notice, { borderColor: p.warn }]}>
          <Text style={{ color: p.text, fontWeight: "700", marginBottom: 6 }}>{t("connect.confirmTitle")}</Text>
          <Text style={{ color: p.text, marginBottom: 4 }}>{t("connect.compareFp")}</Text>
          <Text style={[styles.fp, { color: p.text }]} selectable>
            {deviceId ? fingerprint(deviceId) : "—"}
          </Text>
          <Text style={{ color: p.text, fontFamily: fonts.mono, marginTop: 6 }} selectable>
            wardend pair approve {w.pairId ?? "<id>"}
          </Text>
          <Text style={{ color: p.muted, marginTop: 6, fontSize: 12 }}>{t("connect.waitingApproval")}</Text>
        </View>
      ) : null}
      {w.lastError ? <ErrorText text={w.lastError} url={null} /> : null}
      {paired || waiting ? (
        <Pressable onPress={confirmForget} style={[styles.dangerBtn, { borderColor: p.deny }]}>
          <Text style={{ color: p.deny, fontWeight: "700" }}>{waiting ? t("common.cancel") : t("connect.forgetServer")}</Text>
        </Pressable>
      ) : (
        <>
          <Text style={[styles.hint, { color: p.muted }]}>{t("connect.scanHint")}</Text>
          <BigButton title={busy || w.status === "connecting" ? t("wd.connecting") : t("connect.scan")} color={p.accent} textColor={p.accentText} disabled={busy || w.status === "connecting"} onPress={() => setScan(true)} style={{ flex: 0, marginTop: 4 }} />
          <Text style={[styles.label, { color: p.muted, marginTop: 14 }]}>{t("connect.orPaste")}</Text>
          <TextInput value={link} onChangeText={setLink} autoCapitalize="none" autoCorrect={false} multiline placeholder="wardenclaw://pair?code=…" placeholderTextColor={p.muted} style={[styles.input, styles.codeInput, { color: p.text, backgroundColor: p.input, borderColor: p.border }]} testID="wardend-link" />
          <Text style={[styles.label, { color: p.muted }]}>{t("connect.phoneName")}</Text>
          <TextInput value={name} onChangeText={setName} maxLength={64} style={[styles.input, { color: p.text, backgroundColor: p.input, borderColor: p.border }]} testID="wardend-name" />
          <View style={styles.rowBtns}>
            <Pressable onPress={paste} style={[styles.smallBtn, { borderColor: p.border }]}>
              <Text style={{ color: p.accent, fontWeight: "600" }}>{t("common.paste")}</Text>
            </Pressable>
            <Pressable onPress={() => pair(link)} disabled={busy || !link.trim()} style={[styles.smallBtn, { borderColor: link.trim() ? p.accent : p.border }]} testID="wardend-connect">
              <Text style={{ color: link.trim() ? p.accent : p.muted, fontWeight: "700" }}>{t("connect.connect")}</Text>
            </Pressable>
          </View>
        </>
      )}
      <QrScannerModal
        visible={scan}
        onClose={() => setScan(false)}
        onScanned={(text) => {
          setScan(false);
          pair(text);
        }}
      />
    </Section>
  );
}

/** Error in plain words; for connection and protocol version mismatch errors the raw text (fetch, ConnectException, protocol_mismatch) is under the "Details" expander. */
function ErrorText({ text, url }: { text: string; url: string | null }) {
  const p = usePalette();
  const t = useT();
  const [open, setOpen] = useState(false);
  const ex = explainError(text, url);
  if (!ex) return <Text style={{ color: p.deny, marginTop: 8 }}>{text}</Text>;
  return (
    <View style={{ marginTop: 8 }} testID="net-error">
      <Text style={{ color: p.deny }}>{ex.text}</Text>
      <Pressable onPress={() => setOpen((v) => !v)} accessibilityRole="button" accessibilityState={{ expanded: open }} hitSlop={8} style={{ paddingVertical: 6 }}>
        <Text style={{ color: p.accent, fontSize: 13, fontWeight: "600" }}>{t(open ? "net.hideDetails" : "net.details")}</Text>
      </Pressable>
      {open ? (
        <Text style={{ color: p.muted, fontFamily: fonts.mono, fontSize: 12 }} selectable>
          {ex.detail}
        </Text>
      ) : null}
    </View>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  const p = usePalette();
  return (
    <View style={styles.kv}>
      <Text style={{ color: p.muted, fontSize: 13, width: 104 }}>{label}</Text>
      <Text style={{ color: p.text, fontSize: 13, flex: 1, fontFamily: mono ? fonts.mono : undefined }} selectable>
        {value}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1 },
  header: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", paddingBottom: 12 },
  h1: { fontSize: 28, fontWeight: "800" },
  label: { fontSize: 12, marginBottom: 6, marginTop: 4 },
  hint: { fontSize: 13, lineHeight: 18, marginBottom: 10 },
  input: { borderWidth: 1, borderRadius: 10, paddingHorizontal: 12, paddingVertical: 10, fontSize: 15, marginBottom: 10 },
  codeInput: { minHeight: 70, fontFamily: fonts.mono, fontSize: 12, textAlignVertical: "top" },
  rowBtns: { flexDirection: "row", gap: 10, marginBottom: 6 },
  smallBtn: { borderWidth: 1, borderRadius: 10, paddingHorizontal: 12, paddingVertical: 8 },
  notice: { borderWidth: 1, borderRadius: 10, padding: 12, marginTop: 12 },
  fp: { fontFamily: fonts.mono, fontSize: 20, fontWeight: "700", letterSpacing: 1 },
  kv: { flexDirection: "row", paddingVertical: 6, gap: 8 },
  dangerBtn: { borderWidth: 1, borderRadius: 10, paddingVertical: 12, alignItems: "center", marginTop: 12 },
});
