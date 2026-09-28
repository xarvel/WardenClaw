// SPDX-License-Identifier: GPL-3.0-or-later
// "Judge benchmark" spike: a hidden screen (Mode → "Judge benchmark" at the bottom), a modal above the
// tabs. Downloads weights from HuggingFace on a button press, runs the case set through the selected
// models, results table.
import { useEffect, useState } from "react";
import { Modal, Platform, Pressable, ScrollView, StyleSheet, Switch, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { fonts, usePalette } from "../theme";
import { Section } from "../components";
import { useT } from "../i18n";
import { CATALOG, modelSize } from "../../bench/catalog";
import { CASES, deleteModel, downloadMany, freeSpaceMb, refreshDownloaded, runBench, setBenchOpen, setBenchOpts, useBench } from "../../bench/runner";

const mb = (b: number) => `${(b / 1e6).toFixed(0)} MB`;
const fmt = (x: number | null | undefined, suffix = "") => (x == null ? "—" : `${x}${suffix}`);

export default function BenchModal() {
  const open = useBench((s) => s.open);
  return (
    <Modal visible={open} animationType="slide" onRequestClose={() => setBenchOpen(false)}>
      {open ? <BenchScreen /> : null}
    </Modal>
  );
}

function BenchScreen() {
  const p = usePalette();
  const t = useT();
  const running = useBench((s) => s.running);
  const phase = useBench((s) => s.phase);
  const progress = useBench((s) => s.progress);
  const downloaded = useBench((s) => s.downloaded);
  const dl = useBench((s) => s.dl);
  const results = useBench((s) => s.results);
  const log = useBench((s) => s.log);
  const opts = useBench((s) => s.opts);
  const [sel, setSel] = useState<Record<string, boolean>>({});
  const [free, setFree] = useState<number | null>(null);
  // Retired candidates (spike stage 7) are visible only behind a developer flag.
  const [showRetired, setShowRetired] = useState(false);
  const models = CATALOG.filter((m) => showRetired || !m.retired);
  useEffect(() => {
    refreshDownloaded().catch(() => {});
    freeSpaceMb().then(setFree).catch(() => {});
  }, [running]);
  const selected = CATALOG.filter((m) => sel[m.id]).map((m) => m.id);

  const Btn = ({ title, onPress, disabled }: { title: string; onPress: () => void; disabled?: boolean }) => (
    <Pressable onPress={onPress} disabled={disabled} style={[styles.btn, { borderColor: p.border, opacity: disabled ? 0.4 : 1 }]}>
      <Text style={{ color: p.text, fontWeight: "600", fontSize: 13 }}>{title}</Text>
    </Pressable>
  );

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: p.bg }}>
      <ScrollView contentContainerStyle={{ padding: 16, paddingBottom: 40 }}>
        <View style={styles.header}>
          <Text style={[styles.h1, { color: p.text }]}>{t("bench.title")}</Text>
          <Pressable onPress={() => setBenchOpen(false)} disabled={running}>
            <Text style={{ color: running ? p.muted : p.accent, fontWeight: "700" }}>{t("common.close")}</Text>
          </Pressable>
        </View>
        <Text style={{ color: p.muted, fontSize: 13, marginBottom: 12 }}>{t("bench.hint", { n: CASES.length })}</Text>
        {phase ? (
          <Text style={{ color: p.accent, fontWeight: "700", marginBottom: 8 }} testID="bench-phase">
            {phase} {progress ? `· ${progress}` : ""}
          </Text>
        ) : null}

        <Section title={t("bench.models")}>
          {free != null ? <Text style={{ color: p.muted, fontSize: 12, marginBottom: 6 }}>{t("bench.free", { mb: free })}</Text> : null}
          <View style={[styles.modelRow, { borderColor: p.border }]}>
            <Switch value={showRetired} onValueChange={setShowRetired} disabled={running} testID="bench-show-retired" />
            <Text style={{ color: p.muted, fontSize: 12, flex: 1 }}>{t("bench.showRetired")}</Text>
          </View>
          {models.map((m) => {
            const d = dl[m.id];
            const have = downloaded[m.id];
            return (
              <View key={m.id} style={[styles.modelRow, { borderColor: p.border }]}>
                <Switch value={!!sel[m.id]} onValueChange={(v) => setSel({ ...sel, [m.id]: v })} disabled={running} />
                <View style={{ flex: 1 }}>
                  <Text style={{ color: p.text, fontWeight: "600" }}>{m.title}</Text>
                  <Text style={{ color: p.muted, fontSize: 12 }}>
                    {m.engine} · {mb(modelSize(m))} · {m.license} · {have ? t("bench.downloaded") : d?.status === "downloading" ? `${t("bench.downloading")} ${Math.round((d.received / d.total) * 100)}%` : d?.status === "error" ? `${t("common.error")}: ${d.error}` : t("bench.notDownloaded")}
                  </Text>
                </View>
                {have ? <Btn title={t("bench.delete")} onPress={() => deleteModel(m)} disabled={running} /> : <Btn title={t("bench.download")} onPress={() => downloadMany([m.id])} disabled={running} />}
              </View>
            );
          })}
          <View style={styles.rowBtns}>
            <Btn title={t("bench.downloadSelected")} onPress={() => downloadMany(selected)} disabled={running || !selected.length} />
            <Btn title={t("bench.runSelected")} onPress={() => runBench(selected)} disabled={running || !selected.length} />
            <Btn title={t("bench.runAll")} onPress={() => runBench("downloaded")} disabled={running} />
            {Platform.OS === "ios" ? <Btn title="Run iOS matrix" onPress={() => runBench("ios-matrix")} disabled={running} /> : null}
          </View>
          <View style={styles.rowBtns}>
            <Text style={{ color: p.text, fontSize: 13 }}>{t("bench.threads")}</Text>
            {[2, 4, 6, 8].map((n) => (
              <Pressable key={n} onPress={() => setBenchOpts({ threads: n })} disabled={running} accessibilityRole="radio" accessibilityState={{ selected: opts.threads === n, checked: opts.threads === n, disabled: running }} style={[styles.chip, { borderColor: p.border, backgroundColor: opts.threads === n ? p.accent : "transparent" }]}>
                <Text style={{ color: opts.threads === n ? p.accentText : p.text, fontSize: 12 }}>{n}</Text>
              </Pressable>
            ))}
            <Text style={{ color: p.text, fontSize: 13, marginLeft: 8 }}>{t("bench.grammar")}</Text>
            <Switch value={opts.grammar} onValueChange={(v) => setBenchOpts({ grammar: v })} disabled={running} />
            {Platform.OS === "ios" ? (
              <>
                <Text style={{ color: p.text, fontSize: 13, marginLeft: 8 }}>Metal</Text>
                <Switch value={opts.gpuLayers > 0} onValueChange={(v) => setBenchOpts({ gpuLayers: v ? 99 : 0 })} disabled={running} />
              </>
            ) : null}
          </View>
        </Section>

        <Section title={t("bench.results")}>
          {results.length === 0 ? <Text style={{ color: p.muted }}>{t("bench.noResults")}</Text> : null}
          {results.map((r) => (
            <View key={`${r.model}-${r.threads}-${r.gpuLayers}-${r.grammar}-${r.at}`} style={[styles.result, { borderColor: p.border }]}>
              <Text style={{ color: p.text, fontWeight: "700" }}>
                {r.model} · {r.threads}t{r.engine === "llama" ? ` · GPU ${r.gpuLayers}${r.grammar ? " · GBNF" : " · free"}` : ""}
              </Text>
              {r.error ? <Text style={{ color: p.deny }}>{r.error}</Text> : null}
              <Kv k={t("bench.load")} v={fmt(r.loadMs, " ms")} />
              <Kv k={t("bench.tps")} v={r.engine === "llama" ? `${fmt(r.promptTps)} / ${fmt(r.genTps)}` : t("bench.noGen", { tok: fmt(r.meanPromptTokens) })} />
              <Kv k={t("bench.latency")} v={`${fmt(r.p50Ms, " ms")} / ${fmt(r.p90Ms, " ms")} (${t("bench.first")} ${fmt(r.firstMs, " ms")})`} />
              <Kv k={t("bench.accuracy")} v={`${r.accuracy}% · ${t("bench.accept")} ${r.acceptRate}% · ${t("bench.layered")} ${r.layeredAccept}%`} />
              <Kv k={t("bench.errorsKinds")} v={`unsafe allow ${r.unsafeAllow} · over-block ${r.overBlock} · err ${r.errors}`} />
              <Kv k="JSON" v={r.jsonValidPct == null ? "n/a" : `${r.jsonValidPct}%`} />
              <Kv k={t("bench.battery")} v={`${fmt(r.battery.deltaPct, "%")} · ${fmt(r.battery.deltaMah, " mAh")} · ${fmt(r.battery.avgCurrentMa, " mA")} (idle ${fmt(r.battery.idleCurrentMa, " mA")}) · ≈${fmt(r.battery.estExtraMahPer20, " mAh/20")}`} />
              <Kv k={t("bench.temp")} v={`${fmt(r.battery.maxTempC, " °C")} · thermal ${fmt(r.battery.maxThermalStatus)} · plugged ${fmt(r.battery.plugged)}`} />
              <Kv k="Energy validity" v={r.battery.unplugged ? "unplugged" : r.battery.plugged != null && r.battery.plugged >= 0 ? "INVALID: device was powered" : "unavailable on this device"} />
            </View>
          ))}
        </Section>

        <Section title={t("bench.log")}>
          {log.slice(0, 40).map((l, i) => (
            <Text key={i} style={{ color: p.muted, fontSize: 11, fontFamily: fonts.mono }}>
              {l}
            </Text>
          ))}
        </Section>
      </ScrollView>
    </SafeAreaView>
  );
}

function Kv({ k, v }: { k: string; v: string }) {
  const p = usePalette();
  return (
    <View style={{ flexDirection: "row", gap: 8, paddingVertical: 2 }}>
      <Text style={{ color: p.muted, fontSize: 12, width: 110 }}>{k}</Text>
      <Text style={{ color: p.text, fontSize: 12, flex: 1 }} selectable>
        {v}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  header: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", paddingBottom: 8 },
  h1: { fontSize: 24, fontWeight: "800" },
  modelRow: { flexDirection: "row", alignItems: "center", gap: 8, paddingVertical: 8, borderBottomWidth: StyleSheet.hairlineWidth },
  btn: { borderWidth: 1, borderRadius: 10, paddingHorizontal: 10, paddingVertical: 7 },
  rowBtns: { flexDirection: "row", flexWrap: "wrap", gap: 8, marginTop: 10, alignItems: "center" },
  chip: { borderWidth: 1, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 4 },
  result: { borderWidth: 1, borderRadius: 10, padding: 10, marginBottom: 10 },
});
