// SPDX-License-Identifier: GPL-3.0-or-later
import { useEffect, useState } from "react";
import Slider from "@react-native-community/slider";
import { Alert, AppState, KeyboardAvoidingView, Linking, Platform, Pressable, ScrollView, StyleSheet, Switch, Text, TextInput, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { fonts, usePalette } from "../theme";
import { BigButton, Section, StatusPill } from "../components";
import { useAppState } from "../../core/store";
import { MODES, AppMode } from "../../core/decide";
import { setMode, setThreshold, dismissEscalation, setBiometricMode, refreshOwnerAuth, saveJudgeSettings, deleteJudgeKey, setNoTrashPathsSetting } from "../../core/controller";
import { loadModelPrefs, hasModelKey, ModelPrefs } from "../../core/settings";
import { judgeOnAgentHost, parsePathList } from "../../core/safety";
import { refreshState, setBackgroundNotifications, setNotifPref } from "../../core/background";
import { syncPhonePush } from "../../core/phonePush";
import { watch } from "../../../modules/wardenwatch";
import { useT } from "../i18n";
import { alertActionError } from "../ownerAlert";

// Benchmark entry and the screen protection switch: bench build only (see src/bench/entry.ts)
const bench: typeof import("../../bench/entry") | null = process.env.EXPO_PUBLIC_WARDENCLAW_BENCH === "1" ? require("../../bench/entry") : null;
// Features outside the first release (features.js, docs/release-scope.md): without the build flag
// their blocks are not on the screen and their code is not in the bundle.
const hardwareUi: typeof import("../Hardware") | null = process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_HARDWARE_KEY === "1" ? require("../Hardware") : null;
const watchUi: typeof import("../AppleWatch") | null = process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_APPLE_WATCH === "1" ? require("../AppleWatch") : null;
const phoneJudgeUi: typeof import("../Experimental") | null = process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_PHONE_JUDGE === "1" ? require("../Experimental") : null;

export default function ModeScreen() {
  const p = usePalette();
  const t = useT();
  const mode = useAppState((s) => s.mode);
  const threshold = useAppState((s) => s.threshold);
  const escalation = useAppState((s) => s.escalation);
  const modelReady = useAppState((s) => s.modelReady);
  // the threshold raise confirmation was cancelled: put the slider back to the saved value
  const [sliderKey, setSliderKey] = useState(0);
  const pick = (m: AppMode) => setMode(m).catch(alertActionError);
  const onPickMode = (m: AppMode) => {
    if (m !== "manual" && !modelReady) {
      Alert.alert(t("mode.noModel.title"), t("mode.noModel.body"), [
        { text: t("mode.noModel.enableAnyway"), onPress: () => pick(m) },
        { text: t("common.cancel"), style: "cancel" },
      ]);
      return;
    }
    if (m === "delegate") {
      Alert.alert(t("mode.delegate.confirmTitle"), t("mode.delegate.confirmBody", { threshold }), [
        { text: t("common.cancel"), style: "cancel" },
        { text: t("common.enable"), onPress: () => pick(m) },
      ]);
      return;
    }
    pick(m);
  };
  return (
    <SafeAreaView style={[styles.screen, { backgroundColor: p.bg }]} edges={["top"]}>
      <KeyboardAvoidingView behavior={Platform.OS === "ios" ? "padding" : undefined} style={{ flex: 1 }}>
        <ScrollView contentContainerStyle={{ padding: 16, paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
          <View style={styles.header}>
            <Text style={[styles.h1, { color: p.text }]}>{t("tab.mode")}</Text>
            <StatusPill />
          </View>

          {escalation ? (
            <Pressable onPress={dismissEscalation} style={[styles.notice, { borderColor: p.deny, backgroundColor: p.card, marginBottom: 14 }]}>
              <Text style={{ color: p.deny, fontWeight: "700", marginBottom: 4 }}>{t("mode.escalation")}</Text>
              <Text style={{ color: p.text }}>{escalation}</Text>
              <Text style={{ color: p.muted, fontSize: 12, marginTop: 6 }}>{t("mode.tapToHide")}</Text>
            </Pressable>
          ) : null}

          <Section title={t("mode.section")}>
            <View style={[styles.segment, { borderColor: p.border }]} accessibilityRole="radiogroup">
              {MODES.map((m) => {
                const active = m.id === mode;
                return (
                  <Pressable key={m.id} disabled={!m.enabled} onPress={() => onPickMode(m.id)} style={[styles.segItem, active && { backgroundColor: p.accent }]} accessibilityRole="radio" accessibilityState={{ selected: active, checked: active, disabled: !m.enabled }} testID={`mode-${m.id}`}>
                    <Text style={{ color: active ? p.accentText : m.enabled ? p.text : p.muted, fontWeight: "600", fontSize: 13 }}>{t(m.title)}</Text>
                  </Pressable>
                );
              })}
            </View>
            <Text style={[styles.hintText, { color: p.muted }]}>
              {mode === "manual"
                ? t("mode.hint.manual")
                : mode === "observe"
                  ? t("mode.hint.observe")
                  : t("mode.hint.delegate", { threshold })}
            </Text>
            <Text style={[styles.label, { color: mode === "delegate" ? p.text : p.muted, marginTop: 14 }]}>{t("mode.thresholdLabel", { threshold })}</Text>
            <Slider
              key={sliderKey}
              style={{ width: "100%", height: 40 }}
              minimumValue={0}
              maximumValue={100}
              step={5}
              value={threshold}
              disabled={mode !== "delegate"}
              minimumTrackTintColor={mode === "delegate" ? p.accent : p.disabled}
              maximumTrackTintColor={p.disabled}
              thumbTintColor={mode === "delegate" ? p.accent : p.muted}
              onSlidingComplete={(v) =>
                setThreshold(v).catch((e) => {
                  setSliderKey((k) => k + 1);
                  alertActionError(e);
                })
              }
            />
            <View style={styles.rowBetween}>
              <Text style={{ color: p.muted, fontSize: 12 }}>{t("mode.threshold0")}</Text>
              <Text style={{ color: p.muted, fontSize: 12 }}>{t("mode.threshold100")}</Text>
            </View>
            <BigButton title={t("mode.stop")} color={p.deny} textColor={p.denyText} disabled={mode === "manual"} onPress={() => setMode("manual", "stop").catch(alertActionError)} style={{ flex: 0, marginTop: 14 }} />
            <Text style={{ color: p.muted, fontSize: 12, marginTop: 6, textAlign: "center" }}>
              {mode === "manual" ? t("mode.stopHint.manual") : t("mode.stopHint.other")}
            </Text>
          </Section>

          <BiometricSection />

          <BackgroundSection />

          {hardwareUi ? <hardwareUi.HardwareKeySection /> : null}

          {watchUi && Platform.OS === "ios" ? <watchUi.AppleWatchSection /> : null}

          <ModelSettings />

          <LocalRulesSection />

          {phoneJudgeUi ? <phoneJudgeUi.ExperimentalSection /> : null}

          {bench ? <bench.BenchSection /> : null}
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

function ModelSettings() {
  const p = usePalette();
  const t = useT();
  const modelReady = useAppState((s) => s.modelReady);
  const [prefs, setPrefs] = useState<ModelPrefs | null>(null);
  const [key, setKey] = useState("");
  const [keyStored, setKeyStored] = useState(false);
  const [open, setOpen] = useState(false);
  // A judge on the agent's host is not independent: a warning next to the address, saving still works
  const wardendUrl = useAppState((s) => s.wardend.url);
  const gatewayUrl = useAppState((s) => (s.openclawAdapter && s.hasToken ? s.gatewayUrl : null));
  const agentHost = prefs ? judgeOnAgentHost(prefs.url, [wardendUrl, gatewayUrl]) : null;
  useEffect(() => {
    loadModelPrefs().then(setPrefs);
    hasModelKey().then(setKeyStored);
  }, []);
  // A different URL, model or key: owner confirmation, the autopilot turns off (controller.ts)
  const save = async () => {
    if (!prefs) return;
    try {
      await saveJudgeSettings(prefs, key);
    } catch (e) {
      loadModelPrefs().then(setPrefs);
      return alertActionError(e);
    }
    if (key.trim()) {
      setKey("");
      setKeyStored(true);
    }
    Alert.alert(t("model.saved.title"), t("model.saved.body"));
  };
  const clearKey = async () => {
    await deleteJudgeKey();
    setKeyStored(false);
  };
  return (
    <Section title={t("model.section")}>
      <Pressable onPress={() => setOpen((v) => !v)}>
        <Row label={t("common.status")} value={modelReady ? t("model.ready") : t("model.notReady")} />
        <Row label={t("model.model")} value={!prefs ? "…" : prefs.model || prefs.url ? `${prefs.model || "?"} @ ${prefs.url || "?"}` : t("model.notSet")} mono />
        <Text style={{ color: p.accent, fontSize: 13, marginTop: 4 }}>{open ? t("model.hide") : t("model.edit")}</Text>
      </Pressable>
      {agentHost ? (
        <Text style={[styles.hintText, { color: p.warn }]} accessibilityRole="alert" testID="model-same-host">
          {t("model.sameHost", { host: agentHost })}
        </Text>
      ) : null}
      {open && prefs ? (
        <View style={{ marginTop: 10 }}>
          <Text style={[styles.label, { color: p.muted }]}>{t("model.url")}</Text>
          <TextInput value={prefs.url} onChangeText={(v) => setPrefs({ ...prefs, url: v })} autoCapitalize="none" autoCorrect={false} keyboardType="url" accessibilityHint={t("model.urlHint")} style={[styles.input, { color: p.text, backgroundColor: p.input, borderColor: p.border }]} testID="model-url" />
          <Text style={[styles.hintText, { color: p.muted }]}>{t("model.urlHint")}</Text>
          <Text style={[styles.label, { color: p.muted }]}>{t("model.name")}</Text>
          <TextInput value={prefs.model} onChangeText={(v) => setPrefs({ ...prefs, model: v })} autoCapitalize="none" autoCorrect={false} style={[styles.input, { color: p.text, backgroundColor: p.input, borderColor: p.border }]} testID="model-name" />
          <Text style={[styles.label, { color: p.muted }]}>{t("model.timeout")}</Text>
          <TextInput value={String(Math.round(prefs.timeoutMs / 1000))} onChangeText={(v) => setPrefs({ ...prefs, timeoutMs: Math.max(5, Number(v) || 60) * 1000 })} keyboardType="numeric" style={[styles.input, { color: p.text, backgroundColor: p.input, borderColor: p.border }]} />
          <Text style={[styles.label, { color: p.muted }]}>{t("model.key", { state: keyStored ? t("model.keyStored") : t("model.keyNotSet") })}</Text>
          <TextInput value={key} onChangeText={setKey} secureTextEntry autoCapitalize="none" autoCorrect={false} placeholder="••••••" placeholderTextColor={p.muted} style={[styles.input, { color: p.text, backgroundColor: p.input, borderColor: p.border }]} testID="model-key" />
          <View style={styles.rowBtns}>
            <Pressable onPress={save} style={[styles.smallBtn, { borderColor: p.accent }]}>
              <Text style={{ color: p.accent, fontWeight: "700" }}>{t("common.save")}</Text>
            </Pressable>
            {keyStored ? (
              <Pressable onPress={clearKey} style={[styles.smallBtn, { borderColor: p.deny }]}>
                <Text style={{ color: p.deny, fontWeight: "600" }}>{t("model.deleteKey")}</Text>
              </Pressable>
            ) : null}
          </View>
        </View>
      ) : null}
    </Section>
  );
}

/** Confirmation before signing allow: biometrics or the device passcode (expo-local-authentication). */
function BiometricSection() {
  const p = usePalette();
  const t = useT();
  const mode = useAppState((s) => s.biometricMode);
  const level = useAppState((s) => s.ownerAuth);
  useEffect(() => {
    refreshOwnerAuth();
  }, []);
  const status =
    level === null ? t("bio.level.unknown") : level === "biometric" ? t("bio.level.biometric") : level === "passcode" ? t("bio.level.passcode") : level === "none" ? t("bio.level.none") : t("bio.level.noModule");
  return (
    <Section title={t("bio.section")}>
      <View style={[styles.segment, { borderColor: p.border }]} accessibilityRole="radiogroup">
        {(["risky", "all"] as const).map((m) => {
          const active = m === mode;
          return (
            <Pressable key={m} onPress={() => setBiometricMode(m).catch(alertActionError)} style={[styles.segItem, active && { backgroundColor: p.accent }]} accessibilityRole="radio" accessibilityState={{ selected: active, checked: active }} testID={`bio-${m}`}>
              <Text style={{ color: active ? p.accentText : p.text, fontWeight: "600", fontSize: 13 }}>{t(m === "risky" ? "bio.mode.risky" : "bio.mode.all")}</Text>
            </Pressable>
          );
        })}
      </View>
      <Text style={[styles.hintText, { color: p.muted }]}>{t(mode === "all" ? "bio.hint.all" : "bio.hint.risky")}</Text>
      <Text style={[styles.hintText, { color: level === "none" || level === "unavailable" ? p.deny : p.muted }]}>{status}</Text>
    </Section>
  );
}

function SwitchRow({ label, sub, value, disabled, onChange, testID }: { label: string; sub?: string; value: boolean; disabled?: boolean; onChange: (v: boolean) => void; testID?: string }) {
  const p = usePalette();
  return (
    <View style={[styles.switchRow, { marginTop: 12 }]}>
      <View style={{ flex: 1 }}>
        <Text style={{ color: p.text, fontSize: 15, fontWeight: "600" }}>{label}</Text>
        {sub ? <Text style={{ color: p.muted, fontSize: 12, marginTop: 2 }}>{sub}</Text> : null}
      </View>
      <Switch value={value} disabled={disabled} onValueChange={onChange} accessibilityLabel={label} testID={testID} />
    </View>
  );
}

function SmallButton({ label, onPress, testID }: { label: string; onPress: () => void; testID?: string }) {
  const p = usePalette();
  return (
    <Pressable onPress={onPress} accessibilityRole="button" testID={testID} style={[styles.smallBtn, { borderColor: p.border, alignSelf: "flex-start", marginTop: 10 }]}>
      <Text style={{ color: p.accent, fontWeight: "600" }}>{label}</Text>
    </Pressable>
  );
}

function BackgroundSection() {
  const p = usePalette();
  const t = useT();
  const on = useAppState((s) => s.bgNotify);
  const bg = useAppState((s) => s.bg);
  const notif = useAppState((s) => s.notif);
  const w = useAppState((s) => s.wardend.status);
  const adapter = useAppState((s) => s.openclawAdapter && s.hasToken);
  const paired = w === "connected" || w === "unavailable" || (Platform.OS === "android" && adapter);
  // Back from settings (permission, battery, screen over the lock screen): re-read
  useEffect(() => {
    const sub = AppState.addEventListener("change", (st) => {
      if (st === "active" && Platform.OS === "android") refreshState();
    });
    return () => sub.remove();
  }, []);
  const hint = [styles.hintText, { color: p.muted }];
  const warn = [styles.hintText, { color: p.deny }];
  if (Platform.OS === "ios") {
    // iOS: the system does not keep our own connection alive in the background, hence APNs (src/core/phonePush.ts)
    const st = bg.push;
    const status = !bg.supported
      ? t("bg.unsupported")
      : !paired
        ? t("bg.needsServer")
        : !on
          ? t("conn.off")
          : st.state === "registered"
            ? t("bg.ios.registered")
            : st.state === "registering"
              ? t("bg.ios.registering")
              : st.state === "no-permission"
                ? t("bg.ios.noPermission")
                : st.state === "not-configured"
                  ? t("bg.ios.notConfigured")
                  : st.state === "error"
                    ? t("bg.ios.error", { msg: st.detail ?? "?" })
                    : t("conn.off");
    return (
      <Section title={t("bg.section")}>
        <SwitchRow
          label={t("bg.toggle")}
          sub={status}
          value={on}
          disabled={!bg.supported}
          onChange={(v) => {
            setBackgroundNotifications(v)
              .then(() => syncPhonePush(v))
              .catch(() => {});
          }}
          testID="bg-notify"
        />
        <Text style={hint}>{t("bg.ios.hint")}</Text>
        {on && st.state === "no-permission" ? <SmallButton label={t("bg.openSettings")} onPress={() => Linking.openSettings()} /> : null}
        {on && bg.timeSensitive === false ? <Text style={warn}>{t("bg.ios.timeSensitiveOff")}</Text> : null}
      </Section>
    );
  }
  if (Platform.OS !== "android") return null;
  const status = !bg.supported ? t("bg.unsupported") : !paired ? t("bg.needsServer") : on ? (bg.running ? t("bg.running") : t("bg.notRunning")) : t("conn.off");
  return (
    <Section title={t("bg.section")}>
      <SwitchRow label={t("bg.toggle")} sub={status} value={on} disabled={!bg.supported} onChange={(v) => setBackgroundNotifications(v)} testID="bg-notify" />
      <Text style={hint}>{t("bg.hint")}</Text>
      {on && bg.supported && paired ? (
        <>
          {bg.permission === "denied" ? (
            <>
              <Text style={warn}>{t("bg.permDenied")}</Text>
              <SmallButton label={t("bg.permOpen")} onPress={() => watch?.openNotificationSettings()} testID="notif-open-settings" />
            </>
          ) : null}
          <SwitchRow label={t("bg.showCommand")} value={notif.showCommand} onChange={(v) => setNotifPref("showCommand", v)} testID="notif-show-command" />
          <Text style={hint}>{t("bg.showCommandHint")}</Text>
          <SwitchRow label={t("bg.fullScreen")} value={notif.fullScreen} onChange={(v) => setNotifPref("fullScreen", v)} testID="notif-full-screen" />
          <Text style={hint}>{t("bg.fullScreenHint")}</Text>
          {notif.fullScreen && !bg.fullScreenAllowed ? (
            <>
              <Text style={warn}>{t("bg.fullScreenPerm")}</Text>
              <SmallButton label={t("bg.fullScreenOpen")} onPress={() => watch?.openFullScreenSettings()} testID="notif-full-screen-settings" />
            </>
          ) : null}
          <Text style={hint}>{bg.batteryUnrestricted ? t("bg.batteryOff") : t("bg.batteryOn")}</Text>
          {bg.batteryUnrestricted ? null : <SmallButton label={t("bg.batteryBtn")} onPress={() => watch?.requestIgnoreBatteryOptimizations()} testID="notif-battery" />}
        </>
      ) : null}
    </Section>
  );
}

/** Local rule: trash-put on these paths is always decided by a human (formerly EXPO_PUBLIC_WARDENCLAW_NO_TRASH_PATHS). */
function LocalRulesSection() {
  const p = usePalette();
  const t = useT();
  const saved = useAppState((s) => s.noTrashPaths);
  const [text, setText] = useState(saved.join(", "));
  useEffect(() => setText(saved.join(", ")), [saved]);
  const next = parsePathList(text);
  const dirty = next.join("\n") !== saved.join("\n");
  const save = () =>
    setNoTrashPathsSetting(next)
      .then(() => Alert.alert(t("rules.saved")))
      .catch((e) => {
        setText(saved.join(", "));
        alertActionError(e);
      });
  return (
    <Section title={t("rules.section")}>
      <Text style={[styles.label, { color: p.muted }]}>{t("rules.noTrash.label")}</Text>
      <TextInput value={text} onChangeText={setText} autoCapitalize="none" autoCorrect={false} placeholder="/mnt/shared" placeholderTextColor={p.muted} style={[styles.input, { color: p.text, backgroundColor: p.input, borderColor: p.border }]} testID="rules-no-trash" />
      <Text style={[styles.hintText, { color: p.muted, marginTop: 0 }]}>{t("rules.noTrash.hint")}</Text>
      {dirty ? (
        <Pressable onPress={save} style={[styles.smallBtn, { borderColor: p.accent, alignSelf: "flex-start", marginTop: 10 }]} testID="rules-save">
          <Text style={{ color: p.accent, fontWeight: "700" }}>{t("common.save")}</Text>
        </Pressable>
      ) : null}
    </Section>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  const p = usePalette();
  return (
    <View style={styles.kv}>
      <Text style={{ color: p.muted, fontSize: 13, width: 92 }}>{label}</Text>
      <Text style={{ color: p.text, fontSize: 13, flex: 1, fontFamily: mono ? fonts.mono : undefined }} selectable>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1 },
  header: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", paddingBottom: 12 },
  h1: { fontSize: 28, fontWeight: "800" },
  label: { fontSize: 12, marginBottom: 6, marginTop: 4 },
  input: { borderWidth: 1, borderRadius: 10, paddingHorizontal: 12, paddingVertical: 10, fontSize: 15, marginBottom: 10 },
  codeInput: { minHeight: 90, fontFamily: fonts.mono, fontSize: 12, textAlignVertical: "top" },
  rowBtns: { flexDirection: "row", gap: 10, marginBottom: 6 },
  smallBtn: { borderWidth: 1, borderRadius: 10, paddingHorizontal: 12, paddingVertical: 8 },
  notice: { borderWidth: 1, borderRadius: 10, padding: 12, marginTop: 12 },
  segment: { flexDirection: "row", borderWidth: 1, borderRadius: 12, overflow: "hidden" },
  segItem: { flex: 1, paddingVertical: 10, alignItems: "center" },
  sliderTrack: { height: 6, borderRadius: 3, marginTop: 14, marginBottom: 6, justifyContent: "center" },
  sliderFill: { position: "absolute", left: 0, width: "0%", height: 6, borderRadius: 3 },
  sliderKnob: { position: "absolute", left: 0, width: 22, height: 22, borderRadius: 11, borderWidth: 3 },
  rowBetween: { flexDirection: "row", justifyContent: "space-between" },
  hintText: { fontSize: 13, marginTop: 10, lineHeight: 18 },
  kv: { flexDirection: "row", paddingVertical: 6, gap: 8 },
  dangerBtn: { borderWidth: 1, borderRadius: 10, paddingVertical: 12, alignItems: "center", marginTop: 12 },
  switchRow: { flexDirection: "row", alignItems: "center", gap: 12 },
});
