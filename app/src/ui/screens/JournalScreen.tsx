// SPDX-License-Identifier: GPL-3.0-or-later
import { useEffect, useMemo, useState } from "react";
import { Alert, FlatList, Pressable, StyleSheet, Text, TextInput, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { fonts, usePalette } from "../theme";
import { Badge, formatTime } from "../components";
import { DecidedBy, JournalEntry, countEntries, listEntries, subscribeJournal } from "../../core/journal";
import { clearJournalAsOwner } from "../../core/controller";
import { MsgKey, t, tOr } from "../../core/i18n";
import { UNRATED_SOURCES, entryText, payloadView, proposalText, sourceText, unratedWhy } from "../../core/journalText";
import { useT } from "../i18n";
import { alertActionError } from "../ownerAlert";

const FILTERS: { id: DecidedBy | "all"; title: MsgKey }[] = [
  { id: "all", title: "journal.filter.all" },
  { id: "me", title: "journal.filter.me" },
  { id: "other", title: "journal.filter.other" },
  { id: "timeout", title: "journal.filter.timeout" },
  { id: "agent", title: "journal.filter.agent" },
];

function kindTitle(e: JournalEntry): string {
  switch (e.kind) {
    case "requested":
      return t("journal.kind.requested");
    case "resolved":
      return t(e.decided_by === "me" ? "journal.kind.resolvedMe" : e.decided_by === "timeout" ? "journal.kind.expired" : e.decided_by === "agent" ? "journal.kind.resolvedAgent" : "journal.kind.resolvedOther");
    case "auto_resolved":
      return t(e.decided_by === "agent" ? "journal.kind.resolvedAgent" : "journal.kind.resolvedOther");
    case "verdict":
      return t("journal.kind.verdict");
    case "escalation":
      return t("journal.kind.escalation");
    case "expired":
      return t("journal.kind.expired");
    case "connect":
      return t("journal.kind.connect");
    case "pairing":
      return t("journal.kind.pairing");
    case "error":
      return t("journal.kind.error");
    case "local_opinion":
      // on-device judge entries from a build with it; the string exists only with its flag (features.js)
      return tOr("journal.kind.localOpinion", t("journal.kind.event"));
    default:
      return t("journal.kind.event");
  }
}

function decisionText(d: string | null, kind: JournalEntry["kind"]): string {
  if (!d) return "";
  // in a judge assessment, decision is a proposal, not the outcome: "suggests denying", not "denied"
  if (kind === "verdict") return proposalText(d);
  if (d === "allow-once") return t("journal.dec.allowed");
  if (d === "deny") return t("journal.dec.denied");
  if (d === "timeout") return t("journal.dec.timeout");
  if (d === "allow") return t("journal.dec.proposeAllow");
  if (d === "ask") return t("journal.dec.proposeAsk");
  return d;
}

function Entry({ e }: { e: JournalEntry }) {
  const p = usePalette();
  useT();
  const [open, setOpen] = useState(false);
  // the judge's proposal is muted, only the final decision is colored
  const decisionColor = e.kind === "verdict" ? p.muted : e.decision === "allow-once" ? p.allow : e.decision === "deny" ? p.deny : p.muted;
  const vinfo = verdictInfo(e);
  return (
    <Pressable onPress={() => setOpen((v) => !v)} style={[styles.entry, { backgroundColor: p.card, borderColor: p.border }]}>
      <View style={styles.row}>
        <Text style={[styles.time, { color: p.muted }]}>{formatTime(e.ts)}</Text>
        {e.approval_kind ? <Badge text={e.approval_kind.toUpperCase()} bg={e.approval_kind === "exec" ? p.badgeExec : e.approval_kind === "gate" ? p.badgeGate : p.badgePlugin} color={p.text} /> : null}
      </View>
      <Text style={[styles.title, { color: p.text }]}>
        {kindTitle(e)}
        {e.decision && e.decision !== "?" ? <Text style={{ color: decisionColor }}> · {decisionText(e.decision, e.kind)}</Text> : null}
      </Text>
      <Text style={[styles.summary, { color: p.text }]} numberOfLines={open ? undefined : 2}>{entryText(e)}</Text>
      {vinfo ? (
        <Text style={[styles.meta, { color: p.muted }]}>
          {vinfo.risk === null ? t("feed.chip.unrated", { why: unratedWhy(vinfo.source) }) : `${t("journal.risk", { risk: vinfo.risk })} · ${sourceText(vinfo.source)}`}{vinfo.model ? ` · ${vinfo.model}` : ""} · {t("fmt.seconds", { s: (vinfo.latencyMs / 1000).toFixed(1) })}
        </Text>
      ) : null}
      {vinfo && open ? (
        <>
          {vinfo.explanation ? <Text style={[styles.summary, { color: p.text }]}>{t(vinfo.source === "blocklist" || vinfo.source === "injection" ? "journal.whyFired" : "journal.whatItDoes", { text: vinfo.explanation })}</Text> : null}
          {vinfo.goalFit ? <Text style={[styles.summary, { color: p.text }]}>{t("journal.goal", { text: vinfo.goalFit })}</Text> : null}
        </>
      ) : null}
      {e.latency_ms !== null && e.kind !== "verdict" ? <Text style={[styles.meta, { color: p.muted }]}>{t("journal.latency", { s: (e.latency_ms / 1000).toFixed(1) })}</Text> : null}
      {open && (
        <View style={[styles.details, { borderColor: p.border }]}>
          {e.approval_id ? <Text style={[styles.mono, { color: p.muted }]}>id {e.approval_id}</Text> : null}
          <Text style={[styles.mono, { color: p.muted }]}>hash {e.hash.slice(0, 16)}…  prev {e.prev_hash.slice(0, 16)}…</Text>
          {e.payload ? <Text style={[styles.mono, styles.block, { color: p.text }]} selectable>{payloadView(e.payload)}</Text> : null}
        </View>
      )}
    </Pressable>
  );
}

function verdictInfo(e: JournalEntry): { risk: number | null; source: string; model: string | null; latencyMs: number; explanation: string; goalFit: string } | null {
  if (e.kind !== "verdict" || !e.payload) return null;
  try {
    const v = (JSON.parse(e.payload) as { verdict?: Record<string, unknown> }).verdict;
    if (!v) return null;
    return {
      // old "no model"/"model error" entries wrote 100 as a placeholder: that is not a rating
      risk: typeof v.risk === "number" && !UNRATED_SOURCES.includes(String(v.source)) ? v.risk : null,
      source: String(v.source ?? ""),
      model: typeof v.model === "string" ? v.model : null,
      latencyMs: Number(v.latencyMs ?? 0),
      explanation: typeof v.explanation === "string" ? v.explanation : "",
      goalFit: typeof v.goalFit === "string" ? v.goalFit : "",
    };
  } catch {
    return null;
  }
}

export default function JournalScreen() {
  const p = usePalette();
  const t = useT();
  const [filter, setFilter] = useState<DecidedBy | "all">("all");
  const [search, setSearch] = useState("");
  const [version, setVersion] = useState(0);
  useEffect(() => subscribeJournal(() => setVersion((v) => v + 1)), []);
  const entries = useMemo(() => listEntries({ decidedBy: filter, search }), [filter, search, version]);
  // the whole journal, not the filtered list: "Clear journal" is off only when there is nothing to clear
  const total = useMemo(() => countEntries(), [version]);
  // a destructive dialog first, then the owner check (biometrics or passcode) in the controller
  const confirmClear = () =>
    Alert.alert(t("journal.clear.title"), t("journal.clear.body", { n: total }), [
      { text: t("common.cancel"), style: "cancel" },
      { text: t("journal.clear.btn"), style: "destructive", onPress: () => clearJournalAsOwner().catch(alertActionError) },
    ]);

  return (
    <SafeAreaView style={[styles.screen, { backgroundColor: p.bg }]} edges={["top"]}>
      <View style={styles.header}>
        <Text style={[styles.h1, { color: p.text }]}>{t("tab.journal")}</Text>
        <View style={styles.headerRight}>
          <Text style={{ color: p.muted, fontSize: 13 }}>{t("journal.count", { n: entries.length })}</Text>
          <Pressable onPress={confirmClear} disabled={total === 0} accessibilityRole="button" accessibilityState={{ disabled: total === 0 }} hitSlop={8} testID="journal-clear">
            <Text style={{ color: total === 0 ? p.muted : p.deny, fontSize: 13, fontWeight: "600" }}>{t("journal.clear")}</Text>
          </Pressable>
        </View>
      </View>
      <TextInput
        value={search}
        onChangeText={setSearch}
        placeholder={t("journal.search")}
        placeholderTextColor={p.muted}
        autoCapitalize="none"
        style={[styles.search, { color: p.text, backgroundColor: p.input, borderColor: p.border }]}
      />
      <View style={styles.filters} accessibilityRole="radiogroup">
        {FILTERS.map((f) => {
          const active = f.id === filter;
          return (
            <Pressable key={f.id} onPress={() => setFilter(f.id)} accessibilityRole="radio" accessibilityState={{ selected: active, checked: active }} style={[styles.chip, { borderColor: active ? p.accent : p.border, backgroundColor: active ? p.accent : "transparent" }]}>
              <Text style={{ color: active ? p.accentText : p.text, fontSize: 13, fontWeight: "600" }}>{t(f.title)}</Text>
            </Pressable>
          );
        })}
      </View>
      <FlatList
        data={entries}
        keyExtractor={(e) => String(e.id)}
        renderItem={({ item }) => <Entry e={item} />}
        contentContainerStyle={{ padding: 16, paddingTop: 4, paddingBottom: 40, flexGrow: 1 }}
        ListEmptyComponent={<Text style={{ color: p.muted, textAlign: "center", marginTop: 60 }}>{t("journal.empty")}</Text>}
      />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1 },
  header: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", paddingHorizontal: 16, paddingTop: 8, paddingBottom: 8 },
  headerRight: { alignItems: "flex-end", gap: 4 },
  h1: { fontSize: 28, fontWeight: "800" },
  search: { marginHorizontal: 16, borderWidth: 1, borderRadius: 10, paddingHorizontal: 12, paddingVertical: 8, fontSize: 15 },
  filters: { flexDirection: "row", flexWrap: "wrap", gap: 8, paddingHorizontal: 16, paddingVertical: 10 },
  chip: { borderWidth: 1, borderRadius: 999, paddingHorizontal: 12, paddingVertical: 6 },
  entry: { borderRadius: 14, borderWidth: StyleSheet.hairlineWidth, padding: 12, marginBottom: 10 },
  row: { flexDirection: "row", justifyContent: "space-between", alignItems: "center", marginBottom: 4 },
  time: { fontSize: 12, fontVariant: ["tabular-nums"] },
  title: { fontSize: 15, fontWeight: "700" },
  summary: { fontSize: 14, marginTop: 4 },
  meta: { fontSize: 12, marginTop: 4 },
  details: { borderTopWidth: StyleSheet.hairlineWidth, marginTop: 8, paddingTop: 8, gap: 4 },
  mono: { fontFamily: fonts.mono, fontSize: 11 },
  block: { padding: 8, borderRadius: 8, backgroundColor: "rgba(127,127,127,0.12)" },
});
