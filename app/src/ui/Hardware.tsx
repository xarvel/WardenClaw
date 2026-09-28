// SPDX-License-Identifier: GPL-3.0-or-later
// YubiKey in the UI: (1) the tap modal for "Allow" on a high-risk card,
// (2) the "Hardware key" section on the Mode tab with the binding wizard.
// In both places the key can be tapped (NFC) or plugged into USB-C: the native module listens on
// both transports at once, and useKeyPrompt updates the prompt on USB events (plugged in,
// permission, touch). Expo Go has no native module: we show a clear message, the rest works as
// before.
import { useEffect, useRef, useState } from "react";
import { ActivityIndicator, Alert, Modal, Platform, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import * as Clipboard from "expo-clipboard";
import { fonts, usePalette } from "./theme";
import { BigButton, Section } from "./components";
import { useAppState } from "../core/store";
import { Card } from "../core/approvals";
import { OwnerNotConfirmed, approveWithHardware, bindHardwareKey, refreshServerStatus, unbindHardwareKey } from "../core/controller";
import { headlineText } from "../core/display";
import { coseAlgName, hardwareCoverage } from "../core/hardware";
import { errMsg } from "../core/errMsg";
import { alertActionError } from "./ownerAlert";
import { YubikeyError, YubikeyStatus, cancelYubikey, onYubikeyStatus, yubikeyAvailability } from "../core/hardwareKey";
import { tOr } from "../core/i18n";
import { useT } from "./i18n";

const wardendReason = (r: string) => tOr(`hw.reason.${r}`, r);

/** "Tap or plug in" prompt based on the available transports and USB events, while active. */
function useKeyPrompt(active: boolean): string {
  const t = useT();
  const [usb, setUsb] = useState<YubikeyStatus["state"] | null>(null);
  useEffect(() => {
    if (!active) return setUsb(null);
    return onYubikeyStatus((e) => {
      if (e.transport === "usb") setUsb(e.state);
    });
  }, [active]);
  if (usb && usb !== "permission-denied") return t(`hw.usb.${usb}`);
  const a = yubikeyAvailability();
  if (a.ok && a.nfc && !a.usb) return t(Platform.OS === "ios" ? "hw.tapPromptIos" : "hw.tapPromptNfc");
  if (a.ok && !a.nfc && a.usb) return t("hw.tapPromptUsb");
  return t("hw.tapPrompt");
}

type Phase = { k: "check" } | { k: "unavailable"; msg: string } | { k: "tap" } | { k: "pin"; msg: string | null } | { k: "error"; msg: string; retry: boolean };

/** Modal: "Tap the YubiKey" → the key signs the ticket → send. */
/** onClose(applied): true if wardend accepted the decision, "mock" if the key signed a test card, false if closed. */
export function HardwareTapModal({ card, why, onClose }: { card: Card | null; why: string; onClose: (applied: boolean | "mock") => void }) {
  const p = usePalette();
  const t = useT();
  const key = useAppState((s) => s.hardwareKey);
  const [phase, setPhase] = useState<Phase>({ k: "check" });
  const [pin, setPin] = useState("");
  const alive = useRef(true);
  const prompt = useKeyPrompt(!!card && (phase.k === "check" || phase.k === "tap"));

  const run = async (withPin: string | null) => {
    if (!card) return;
    setPhase({ k: "tap" });
    try {
      const r = await approveWithHardware(card, withPin ?? (key?.requireUv ? pin : null));
      if (!alive.current) return;
      if (r.applied) return onClose(true);
      if (r.status.startsWith("mock signed")) {
        Alert.alert(t("hw.mockSigned.title"), t("hw.mockSigned.body"));
        return onClose("mock");
      }
      if (r.retry) return setPhase({ k: "error", msg: wardendReason(r.status), retry: true });
      Alert.alert(t("feed.alreadyDecided"), t("feed.alreadyDecidedBody", { status: r.status }));
      onClose(false);
    } catch (e) {
      if (!alive.current) return;
      if (e instanceof OwnerNotConfirmed) return setPhase({ k: "error", msg: e.message, retry: true });
      if (e instanceof YubikeyError && (e.code === "PIN_REQUIRED" || e.code === "PIN_INVALID")) return setPhase({ k: "pin", msg: e.code === "PIN_INVALID" ? t("hw.pinInvalid") : null });
      if (e instanceof YubikeyError && e.code === "CANCELLED") return;
      setPhase({ k: "error", msg: errMsg(e), retry: !(e instanceof YubikeyError && (e.code === "NO_MODULE" || e.code === "IOS_UNSUPPORTED")) });
    }
  };

  useEffect(() => {
    alive.current = true;
    if (!card) return;
    setPin("");
    const a = yubikeyAvailability();
    if (!a.ok) setPhase({ k: "unavailable", msg: a.message });
    else if (!key) setPhase({ k: "unavailable", msg: t("hw.notBoundTab") });
    else if (key.requireUv) setPhase({ k: "pin", msg: null });
    else run(null);
    return () => {
      alive.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [card?.id]);

  const close = () => {
    cancelYubikey();
    onClose(false);
  };

  return (
    <Modal visible={!!card} transparent animationType="slide" onRequestClose={close}>
      <View style={styles.backdrop}>
        <View style={[styles.sheet, { backgroundColor: p.card, borderColor: p.border }]}>
          <Text style={[styles.title, { color: p.text }]}>{t("hw.tap.title")}</Text>
          <Text style={{ color: p.muted, fontSize: 13, marginBottom: 10 }} numberOfLines={3}>
            {card ? (card.view ? headlineText(card.view) : card.summary) : ""}
          </Text>
          {why ? <Text style={{ color: p.warn, fontSize: 13, marginBottom: 12 }}>{t("hw.highRisk", { why })}</Text> : null}
          {phase.k === "check" || phase.k === "tap" ? (
            <View style={styles.center}>
              <ActivityIndicator size="large" color={p.accent} />
              <Text style={[styles.big, { color: p.text }]}>{prompt}</Text>
              <Text style={{ color: p.muted, fontSize: 13, textAlign: "center" }}>
                {key ? `${key.name} · ${coseAlgName(key.alg)}` : ""}
                {"\n"}{t("hw.tapHold")}
              </Text>
            </View>
          ) : phase.k === "pin" ? (
            <View>
              <Text style={{ color: p.text, marginBottom: 6 }}>{t("hw.pinLabel")}{phase.msg ? `: ${phase.msg}` : ""}</Text>
              <TextInput value={pin} onChangeText={setPin} secureTextEntry keyboardType="number-pad" autoFocus style={[styles.input, { color: p.text, backgroundColor: p.input, borderColor: p.border }]} />
              <BigButton title={t("hw.applyKey")} color={p.allow} textColor={p.allowText} disabled={pin.length < 4} onPress={() => run(pin)} style={{ flex: 0 }} />
            </View>
          ) : (
            <Text style={{ color: phase.k === "unavailable" ? p.warn : p.deny, fontSize: 14, marginBottom: 10 }}>{phase.msg}</Text>
          )}
          <View style={styles.rowBtns}>
            {phase.k === "error" && phase.retry ? <BigButton title={t("hw.again")} color={p.allow} textColor={p.allowText} onPress={() => run(pin || null)} /> : null}
            <BigButton title={phase.k === "unavailable" ? t("common.close") : t("common.cancel")} color={p.disabled} textColor={p.text} onPress={close} />
          </View>
          {phase.k === "unavailable" ? <Text style={{ color: p.muted, fontSize: 12, marginTop: 8 }}>{t("hw.denyWithoutKey")}</Text> : null}
        </View>
      </View>
    </Modal>
  );
}

type WizardStep = { k: "intro" } | { k: "tap" } | { k: "done"; blob: string } | { k: "error"; msg: string };

/** "Hardware key" section on the Mode tab: status and binding wizard. */
export function HardwareKeySection() {
  const p = usePalette();
  const t = useT();
  const key = useAppState((s) => s.hardwareKey);
  const serverHw = useAppState((s) => s.serverHw);
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState<WizardStep>({ k: "intro" });
  const [name, setName] = useState("YubiKey 5 NFC");
  const [pin, setPin] = useState("");
  const avail = yubikeyAvailability();
  const prompt = useKeyPrompt(open && step.k === "tap");
  // the server decides what the key actually protects: number of require_hardware rules from /v1/status
  useEffect(() => {
    if (key) void refreshServerStatus();
  }, [key]);
  const cover = hardwareCoverage(serverHw, key?.credentialId ?? null);

  const start = async () => {
    setStep({ k: "tap" });
    try {
      const k = await bindHardwareKey(name, pin || null);
      setStep({ k: "done", blob: k.blob });
    } catch (e) {
      if (e instanceof YubikeyError && e.code === "CANCELLED") return setStep({ k: "intro" });
      if (e instanceof YubikeyError && e.code === "PIN_REQUIRED") return setStep({ k: "error", msg: t("hw.pinSetError") });
      setStep({ k: "error", msg: errMsg(e) });
    }
  };
  const close = () => {
    cancelYubikey();
    setOpen(false);
    setStep({ k: "intro" });
    setPin("");
  };
  const unbind = () =>
    Alert.alert(t("hw.unbind.title"), t("hw.unbind.body"), [
      { text: t("common.cancel"), style: "cancel" },
      { text: t("hw.unbind.btn"), style: "destructive", onPress: () => unbindHardwareKey().catch(alertActionError) },
    ]);

  return (
    <Section title={t("hw.section")}>
      {key ? (
        <>
          <Text style={{ color: p.text, fontSize: 15, fontWeight: "600" }}>{key.name}</Text>
          <Text style={{ color: p.muted, fontSize: 12, marginTop: 4, fontFamily: fonts.mono }} selectable>
            {coseAlgName(key.alg)} · {key.credentialId.slice(0, 20)}… · {key.requireUv ? t("hw.withPin") : t("hw.touch")}
          </Text>
          <Text style={[styles.hint, { color: cover.rules === "none" ? p.warn : p.text, fontWeight: cover.rules === "none" ? "700" : "400" }]} testID="hw-coverage">
            {cover.rules === "unknown"
              ? t("hw.server.unknown")
              : cover.rules === "none"
                ? t("hw.server.none")
                : cover.named
                  ? t("hw.server.someNamed", { list: cover.named.map((r) => (r.minScore === null ? r.label : t("hw.server.ruleByScore", { rule: r.label, n: r.minScore }))).join("; ") })
                  : t("hw.server.some", { n: cover.count })}
          </Text>
          {cover.keyKnown !== null ? <Text style={[styles.hint, { color: cover.keyKnown ? p.muted : p.warn }]}>{t(cover.keyKnown ? "hw.server.keyKnown" : "hw.server.keyUnknown")}</Text> : null}
          <Text style={[styles.hint, { color: p.muted }]}>{t("hw.server.scoreNote")}</Text>
          <View style={styles.rowBtns}>
            <Pressable onPress={() => Clipboard.setStringAsync(key.blob).then(() => Alert.alert(t("hw.copied"), t("hw.copiedBody")))} style={[styles.smallBtn, { borderColor: p.border }]}>
              <Text style={{ color: p.text, fontWeight: "600" }}>{t("hw.copyBlob")}</Text>
            </Pressable>
            <Pressable onPress={unbind} style={[styles.smallBtn, { borderColor: p.deny }]}>
              <Text style={{ color: p.deny, fontWeight: "600" }}>{t("hw.unbind.btn")}</Text>
            </Pressable>
          </View>
        </>
      ) : (
        <>
          <Text style={{ color: p.text, fontSize: 14 }}>{t("hw.intro")}</Text>
          {!avail.ok ? <Text style={{ color: p.warn, fontSize: 13, marginTop: 8 }}>{avail.message}</Text> : avail.note ? <Text style={{ color: p.muted, fontSize: 13, marginTop: 8 }}>{avail.note}</Text> : null}
          <BigButton title={t("hw.bind")} color={p.accent} textColor={p.accentText} disabled={!avail.ok} onPress={() => setOpen(true)} style={{ flex: 0, marginTop: 12 }} />
        </>
      )}

      <Modal visible={open} transparent animationType="slide" onRequestClose={close}>
        <View style={styles.backdrop}>
          <View style={[styles.sheet, { backgroundColor: p.card, borderColor: p.border }]}>
            <Text style={[styles.title, { color: p.text }]}>{t("hw.bindTitle")}</Text>
            {step.k === "intro" || step.k === "error" ? (
              <>
                <Text style={{ color: p.muted, fontSize: 12, marginBottom: 4 }}>{t("hw.name")}</Text>
                <TextInput value={name} onChangeText={setName} style={[styles.input, { color: p.text, backgroundColor: p.input, borderColor: p.border }]} />
                <Text style={{ color: p.muted, fontSize: 12, marginBottom: 4 }}>{t("hw.pinBindLabel")}</Text>
                <TextInput value={pin} onChangeText={setPin} secureTextEntry keyboardType="number-pad" placeholder={t("hw.noPin")} placeholderTextColor={p.muted} style={[styles.input, { color: p.text, backgroundColor: p.input, borderColor: p.border }]} />
                {step.k === "error" ? <Text style={{ color: p.deny, marginBottom: 10 }}>{step.msg}</Text> : null}
                <BigButton title={t("hw.tapBtn")} color={p.accent} textColor={p.accentText} onPress={start} style={{ flex: 0 }} />
              </>
            ) : step.k === "tap" ? (
              <View style={styles.center}>
                <ActivityIndicator size="large" color={p.accent} />
                <Text style={[styles.big, { color: p.text }]}>{prompt}</Text>
                <Text style={{ color: p.muted, fontSize: 13, textAlign: "center" }}>{t("hw.bindTapHint")}</Text>
              </View>
            ) : (
              <>
                <Text style={{ color: p.ok, fontWeight: "700", marginBottom: 8 }}>{t("hw.bound")}</Text>
                <Text style={{ color: p.text, fontSize: 13, marginBottom: 8 }}>
                  {t("hw.registerHint")}
                </Text>
                <Text style={[styles.code, { color: p.text, borderColor: p.border }]} selectable numberOfLines={4}>
                  wardend hw-register '{step.blob}'
                </Text>
                <BigButton title={t("hw.copyCmd")} color={p.accent} textColor={p.accentText} onPress={() => Clipboard.setStringAsync(`wardend hw-register '${step.blob}'`)} style={{ flex: 0, marginTop: 10 }} />
              </>
            )}
            <View style={styles.rowBtns}>
              <BigButton title={step.k === "done" ? t("common.done") : t("common.cancel")} color={p.disabled} textColor={p.text} onPress={close} />
            </View>
          </View>
        </View>
      </Modal>
    </Section>
  );
}

const styles = StyleSheet.create({
  backdrop: { flex: 1, justifyContent: "flex-end", backgroundColor: "rgba(0,0,0,0.45)" },
  sheet: { borderTopLeftRadius: 20, borderTopRightRadius: 20, borderWidth: StyleSheet.hairlineWidth, padding: 20, paddingBottom: 32 },
  title: { fontSize: 20, fontWeight: "800", marginBottom: 8 },
  center: { alignItems: "center", gap: 12, paddingVertical: 16 },
  big: { fontSize: 18, fontWeight: "700", textAlign: "center" },
  input: { borderWidth: 1, borderRadius: 10, paddingHorizontal: 12, paddingVertical: 10, fontSize: 15, marginBottom: 10 },
  rowBtns: { flexDirection: "row", gap: 10, marginTop: 14 },
  smallBtn: { borderWidth: 1, borderRadius: 10, paddingHorizontal: 12, paddingVertical: 8 },
  hint: { fontSize: 13, marginTop: 8, lineHeight: 18 },
  code: { fontFamily: fonts.mono, fontSize: 11, borderWidth: 1, borderRadius: 8, padding: 8 },
});
