// SPDX-License-Identifier: GPL-3.0-or-later
// "Experimental: on-device judge" settings. Off by default. The local model only advises: its
// opinion is shown on the card in a separate panel, the buttons and the signature stay with the human.
import { useEffect, useState } from "react";
import { Alert, Pressable, StyleSheet, Switch, Text, View } from "react-native";
import { usePalette } from "./theme";
import { useT } from "./i18n";
import { Section } from "./components";
import { EXP_MODELS, ExpModelId, LocalJudgeMode, modelsForMode, saveLocalJudgeSettings, useLJ } from "../localjudge/state";
import { cancelDownload, checkModel, deleteModelFiles, downloadModel, expModelSize, freeBytes } from "../localjudge/files";
import { refreshLocalModels, resetLocalJudge } from "../localjudge/runtime";
import { errMsg } from "../core/errMsg";
import type { MsgKey } from "../core/i18n";

const MODES: { id: LocalJudgeMode; title: MsgKey }[] = [
  { id: "qwen4", title: "exp.mode.qwen4" },
  { id: "kevm", title: "exp.mode.kevm" },
  { id: "both", title: "exp.mode.both" },
];
const mb = (b: number) => `${Math.round(b / 1e6)} MB`;

export function ExperimentalSection() {
  const p = usePalette();
  const t = useT();
  const enabled = useLJ((s) => s.enabled);
  const mode = useLJ((s) => s.mode);
  const inMemory = useLJ((s) => s.inMemory);
  const [free, setFree] = useState<number | null>(null);
  const models = useLJ((s) => s.models);
  const anyBusy = Object.values(models).some((m) => m.state === "downloading" || m.state === "verifying");
  useEffect(() => {
    freeBytes().then(setFree).catch(() => {});
  }, [anyBusy]);
  useEffect(() => {
    if (enabled) refreshLocalModels().catch(() => {});
  }, [enabled, mode]);

  const toggle = async (on: boolean) => {
    await saveLocalJudgeSettings({ enabled: on });
    await resetLocalJudge();
  };
  const pickMode = async (m: LocalJudgeMode) => {
    await saveLocalJudgeSettings({ mode: m });
    await resetLocalJudge();
  };

  return (
    <Section title={t("exp.section")}>
      <View style={styles.switchRow}>
        <View style={{ flex: 1 }}>
          <Text style={{ color: p.text, fontSize: 15, fontWeight: "600" }}>{t("exp.toggle")}</Text>
          <Text style={{ color: p.muted, fontSize: 12, marginTop: 2 }}>{enabled ? t("exp.on") : t("exp.off")}</Text>
        </View>
        <Switch value={enabled} onValueChange={(v) => void toggle(v)} testID="exp-local-judge" />
      </View>
      <Text style={[styles.hint, { color: p.muted }]}>{t("exp.caption")}</Text>
      {enabled ? (
        <>
          <View style={[styles.segment, { borderColor: p.border, marginTop: 12 }]} accessibilityRole="radiogroup">
            {MODES.map((m) => {
              const active = m.id === mode;
              return (
                <Pressable key={m.id} onPress={() => void pickMode(m.id)} style={[styles.segItem, active && { backgroundColor: p.accent }]} accessibilityRole="radio" accessibilityState={{ selected: active, checked: active }} testID={`exp-mode-${m.id}`}>
                  <Text style={{ color: active ? p.accentText : p.text, fontWeight: "600", fontSize: 12, textAlign: "center" }}>{t(m.title)}</Text>
                </Pressable>
              );
            })}
          </View>
          <Text style={[styles.hint, { color: p.muted }]}>{t(mode === "qwen4" ? "exp.modeHint.qwen4" : mode === "kevm" ? "exp.modeHint.kevm" : "exp.modeHint.both")}</Text>
          {modelsForMode(mode).map((id) => (
            <ModelRow key={id} id={id} />
          ))}
          {free != null ? <Text style={[styles.hint, { color: p.muted }]}>{t("exp.free", { mb: Math.floor(free / 1e6) })}</Text> : null}
          <Text style={[styles.hint, { color: p.muted }]}>{t("exp.inMemory", { list: inMemory.length ? inMemory.map((m) => EXP_MODELS[m].title).join(", ") : "—" })}</Text>
          <View style={[styles.warn, { borderColor: p.warn }]}>
            <Text style={{ color: p.warn, fontWeight: "700", marginBottom: 4 }}>{t("exp.heat.title")}</Text>
            <Text style={{ color: p.text, fontSize: 13, lineHeight: 18 }}>{t("exp.heat.body")}</Text>
          </View>
        </>
      ) : null}
    </Section>
  );
}

function ModelRow({ id }: { id: ExpModelId }) {
  const p = usePalette();
  const t = useT();
  const st = useLJ((s) => s.models[id]);
  const total = expModelSize(id);
  const busy = st.state === "downloading" || st.state === "verifying";
  const status =
    st.state === "ready"
      ? t("exp.st.ready")
      : st.state === "unverified"
        ? t("exp.st.unverified")
        : st.state === "downloading"
          ? t("exp.st.downloading", { pct: Math.floor((st.received / Math.max(1, total)) * 100), got: mb(st.received), total: mb(total) })
          : st.state === "verifying"
            ? t("exp.st.verifying")
            : st.state === "corrupt"
              ? t("exp.st.corrupt")
              : st.state === "error"
                ? `${t("common.error")}: ${st.error ?? "?"}`
                : t("exp.st.missing");
  const download = () =>
    downloadModel(id).catch((e) => {
      if (errMsg(e) !== "cancelled") Alert.alert(t("exp.dlFailed"), errMsg(e));
    });
  const del = () =>
    Alert.alert(t("exp.deleteTitle"), t("exp.deleteBody", { model: EXP_MODELS[id].title, size: mb(total) }), [
      { text: t("common.cancel"), style: "cancel" },
      {
        text: t("exp.delete"),
        style: "destructive",
        onPress: async () => {
          await resetLocalJudge();
          await deleteModelFiles(id);
        },
      },
    ]);
  const have = st.state === "ready" || st.state === "unverified" || st.state === "corrupt";
  return (
    <View style={[styles.modelRow, { borderColor: p.border }]} testID={`exp-model-${id}`}>
      <View style={{ flex: 1 }}>
        <Text style={{ color: p.text, fontWeight: "600" }}>
          {EXP_MODELS[id].title} · {mb(total)}
        </Text>
        <Text style={{ color: st.state === "ready" ? p.allow : st.state === "corrupt" || st.state === "error" ? p.deny : p.muted, fontSize: 12, marginTop: 2 }}>{status}</Text>
        {st.state === "downloading" ? (
          <View style={[styles.bar, { backgroundColor: p.border }]}>
            <View style={[styles.barFill, { backgroundColor: p.accent, width: `${Math.min(100, (st.received / Math.max(1, total)) * 100)}%` }]} />
          </View>
        ) : null}
      </View>
      <View style={{ gap: 6 }}>
        {st.state === "downloading" ? (
          <Btn title={t("common.cancel")} onPress={() => void cancelDownload()} />
        ) : !have ? (
          <Btn title={t("exp.download")} onPress={() => void download()} disabled={busy} />
        ) : (
          <>
            {st.state !== "ready" ? <Btn title={t("exp.verify")} onPress={() => void checkModel(id, true)} disabled={busy} /> : null}
            <Btn title={t("exp.delete")} onPress={del} disabled={busy} danger />
          </>
        )}
      </View>
    </View>
  );
}

function Btn({ title, onPress, disabled, danger }: { title: string; onPress: () => void; disabled?: boolean; danger?: boolean }) {
  const p = usePalette();
  return (
    <Pressable onPress={onPress} disabled={disabled} style={[styles.btn, { borderColor: danger ? p.deny : p.accent, opacity: disabled ? 0.4 : 1 }]}>
      <Text style={{ color: danger ? p.deny : p.accent, fontWeight: "600", fontSize: 13 }}>{title}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  switchRow: { flexDirection: "row", alignItems: "center", gap: 12 },
  hint: { fontSize: 13, marginTop: 10, lineHeight: 18 },
  segment: { flexDirection: "row", borderWidth: 1, borderRadius: 12, overflow: "hidden" },
  segItem: { flex: 1, paddingVertical: 10, paddingHorizontal: 4, alignItems: "center", justifyContent: "center" },
  modelRow: { flexDirection: "row", alignItems: "center", gap: 10, borderTopWidth: StyleSheet.hairlineWidth, paddingVertical: 10, marginTop: 10 },
  bar: { height: 4, borderRadius: 2, marginTop: 6, overflow: "hidden" },
  barFill: { height: 4 },
  btn: { borderWidth: 1, borderRadius: 10, paddingHorizontal: 12, paddingVertical: 6, alignItems: "center" },
  warn: { borderWidth: 1, borderRadius: 10, padding: 10, marginTop: 12 },
});
