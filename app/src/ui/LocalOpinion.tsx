// SPDX-License-Identifier: GPL-3.0-or-later
// Experimental: the "On-device opinion (experimental)" panel on the card. It only shows the local
// model's opinion: there are no buttons here, it has no effect on the human decision or the signature.
import { useEffect } from "react";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";
import { usePalette } from "./theme";
import { useT } from "./i18n";
import { CardOpinions, EXP_MODELS, ExpModelId, modelsForMode, Opinion, useLJ } from "../localjudge/state";
import { requestExplanation } from "../localjudge/runtime";
import type { t as tFn } from "../core/i18n";

const isOp = (v: CardOpinions[ExpModelId]): v is Opinion => !!v && v !== "pending" && !("error" in v);

export function LocalOpinionBar({ cardId, open }: { cardId: string; open: boolean }) {
  const p = usePalette();
  const t = useT();
  const enabled = useLJ((s) => s.enabled);
  const mode = useLJ((s) => s.mode);
  const op = useLJ((s) => s.opinions[cardId]);
  const models = useLJ((s) => s.models);
  const wantsQwen = modelsForMode(mode).includes("qwen4");
  useEffect(() => {
    if (!enabled || !wantsQwen) return;
    requestExplanation(cardId, open);
    return () => requestExplanation(cardId, false);
  }, [cardId, open, enabled, wantsQwen]);
  if (!enabled) return null;
  const list = modelsForMode(mode);
  return (
    <View style={[styles.box, { borderColor: p.border }]} testID="local-opinion">
      <Text style={[styles.title, { color: p.muted }]}>{t("exp.opinion.title")}</Text>
      {list.map((m) => {
        const v = op?.[m];
        const ready = models[m].state === "ready";
        return (
          <View key={m} style={styles.row}>
            <Text style={[styles.model, { color: p.text }]}>{EXP_MODELS[m].title}</Text>
            {!ready ? (
              <Text style={[styles.val, { color: p.muted }]}>{t("exp.opinion.noModel")}</Text>
            ) : v === undefined || v === "pending" ? (
              <View style={{ flexDirection: "row", alignItems: "center", flex: 1 }}>
                <ActivityIndicator size="small" color={p.muted} />
                <Text style={[styles.val, { color: p.muted, marginLeft: 6 }]}>{v === "pending" ? t("exp.opinion.thinking") : t("exp.opinion.waiting")}</Text>
              </View>
            ) : isOp(v) ? (
              <Text style={[styles.val, { color: v.decision === "allow" ? p.text : v.decision === "ask" ? p.warn : p.deny }]}>
                {decisionLabel(t, v)} · {t("exp.opinion.risk", { risk: v.risk })} · {t("fmt.seconds", { s: (v.ms / 1000).toFixed(1) })}
                {v.loadMs != null ? ` (+${t("exp.opinion.load", { s: (v.loadMs / 1000).toFixed(1) })})` : ""}
                {v.flags?.length ? `\n${t("exp.opinion.flags", { flags: v.flags.join(", ") })}` : ""}
              </Text>
            ) : (
              <Text style={[styles.val, { color: p.deny }]}>{t("common.error")}: {v.error}</Text>
            )}
          </View>
        );
      })}
      {open && wantsQwen && isOp(op?.qwen4) ? (
        op?.explain === undefined || op.explain === "pending" ? (
          <View style={[styles.row, { marginTop: 4 }]}>
            <ActivityIndicator size="small" color={p.muted} />
            <Text style={[styles.val, { color: p.muted, marginLeft: 6 }]}>{t("exp.opinion.explaining")}</Text>
          </View>
        ) : "error" in op.explain ? (
          <Text style={[styles.val, { color: p.deny, marginTop: 4 }]}>{t("common.error")}: {op.explain.error}</Text>
        ) : (
          <View style={{ marginTop: 4, gap: 4 }}>
            {op.explain.reason ? <Text style={[styles.val, { color: p.text }]}>{op.explain.reason}</Text> : null}
            {op.explain.explanation ? (
              <Text style={[styles.val, { color: p.text }]}>
                <Text style={{ color: p.muted }}>{t("feed.whatItDoes")}</Text>
                {op.explain.explanation}
              </Text>
            ) : null}
            {op.explain.goalFit ? (
              <Text style={[styles.val, { color: p.text }]}>
                <Text style={{ color: p.muted }}>{t("feed.goalFit")}</Text>
                {op.explain.goalFit}
              </Text>
            ) : null}
            <Text style={[styles.foot, { color: p.muted }]}>{t("exp.opinion.explainTime", { s: (op.explain.ms / 1000).toFixed(1) })}</Text>
          </View>
        )
      ) : null}
      <Text style={[styles.foot, { color: p.muted }]}>{t("exp.opinion.advisory")}</Text>
    </View>
  );
}

function decisionLabel(t: typeof tFn, v: Opinion): string {
  // Kev-multi is only a risk pre-filter: its "allow" means "no risk flags", not "OK to approve".
  if (v.model === "kevm") return v.decision === "allow" ? t("exp.opinion.kevClear") : t("exp.opinion.kevFlag", { decision: t(v.decision === "deny" ? "verdict.deny" : "verdict.ask") });
  return t(v.decision === "allow" ? "verdict.allow" : v.decision === "deny" ? "verdict.deny" : "verdict.ask");
}

const styles = StyleSheet.create({
  box: { borderWidth: 1, borderStyle: "dashed", borderRadius: 10, padding: 10, marginTop: 10, gap: 4 },
  title: { fontSize: 11, fontWeight: "700", textTransform: "uppercase", letterSpacing: 0.5 },
  row: { flexDirection: "row", alignItems: "flex-start", gap: 8 },
  model: { fontSize: 13, fontWeight: "600", width: 84 },
  val: { fontSize: 13, flexShrink: 1 },
  foot: { fontSize: 11, marginTop: 2 },
});
