// SPDX-License-Identifier: GPL-3.0-or-later
// Pieces of a card that are not the card itself: the command, the verdict, the environment, the technical layer.
import { useMemo, type ReactNode } from "react";
import { ActivityIndicator, Pressable, Text, View } from "react-native";
import { Palette, usePalette } from "../theme";
import { formatTtl } from "../components";
import { Card, Provenance, categoryLabel, provenanceFacts } from "../../core/approvals";
import { Verdict, isUnrated, riskTone } from "../../core/decide";
import { markOdd, mixedRuns, sanitizeText, type CommandView, type EnvView, type MixedRun, type Part } from "../../core/display";
import { MsgKey } from "../../core/i18n";
import { useT } from "../i18n";
import { styles } from "./styles";
import { TTL_URGENT_MS } from "./timing";

// ---------------------------------------------------------------------------
// Assessment (not signed): verdict of a rule ("Rule: …") or a model ("Model: …"), a chip in words
// and details. A rule is deterministic and is not passed off as a model opinion.
// ---------------------------------------------------------------------------
export const isRuleVerdict = (v: Verdict) => v.source === "blocklist" || v.source === "injection";

export function AssessmentChip({ v }: { v: Verdict | "pending" | undefined }) {
  const p = usePalette();
  const t = useT();
  if (!v) return null;
  const rule = v !== "pending" && isRuleVerdict(v);
  const who = <Text style={[styles.assessLabel, { color: p.text }]}>{t(rule ? "feed.assess.rule" : "feed.assess.model")}</Text>;
  if (v === "pending") {
    return (
      <View style={styles.chipRow}>
        {who}
        <ActivityIndicator size="small" color={p.muted} />
        <Text style={{ color: p.muted, fontSize: 13, marginLeft: 8 }}>{t("feed.judgeThinking")}</Text>
      </View>
    );
  }
  let label: string;
  let bg: string;
  let fg: string;
  if (rule) {
    label = t(v.source === "injection" ? "feed.chip.injection" : "feed.chip.blocklist");
    bg = p.riskHigh;
    fg = p.riskHighText;
  } else if (isUnrated(v)) {
    const why: MsgKey = v.source === "manual" ? "feed.chip.why.manual" : v.source === "model-error" ? "feed.chip.why.modelError" : v.source === "no-time" ? "feed.chip.why.noTime" : "feed.chip.why.noModel";
    label = t("feed.chip.unrated", { why: t(why) });
    bg = p.unrated;
    fg = p.unratedText;
  } else {
    const risk = v.risk ?? 0;
    const tone = riskTone(risk);
    label = t(tone === "low" ? "feed.chip.low" : tone === "mid" ? "feed.chip.mid" : "feed.chip.high", { risk });
    bg = tone === "low" ? p.riskLow : tone === "mid" ? p.riskMid : p.riskHigh;
    fg = tone === "low" ? p.riskLowText : tone === "mid" ? p.riskMidText : p.riskHighText;
  }
  const decision = v.source === "model" ? t("feed.judgeSays", { decision: t(v.decision === "allow" ? "verdict.allow" : v.decision === "deny" ? "verdict.deny" : "verdict.ask") }) : null;
  return (
    <View style={styles.chipRow}>
      {who}
      <View style={[styles.chip, { backgroundColor: bg }]} accessibilityLabel={label}>
        <Text style={[styles.chipText, { color: fg }]}>{label}</Text>
      </View>
      {decision ? <Text style={{ color: p.text, fontSize: 13, fontWeight: "600", marginLeft: 8, flexShrink: 1 }}>{decision}</Text> : null}
    </View>
  );
}

export function AssessmentDetails({ v, open }: { v: Verdict | "pending" | undefined; open: boolean }) {
  const p = usePalette();
  const t = useT();
  if (!v || v === "pending") return null;
  const srcText = v.source === "blocklist" ? t("src.blocklist") : v.source === "injection" ? t("src.injection") : v.source === "model" ? v.model ?? t("src.model") : v.source === "model-error" ? t("src.modelError") : v.source === "no-model" ? t("src.noModel") : v.source === "no-time" ? t("src.noTime") : t("mode.manual");
  return (
    <View>
      {v.source !== "manual" && (open || !isRuleVerdict(v)) ? <Text style={{ color: p.text, fontSize: 13, marginTop: 4 }}>{sanitizeText(v.reason)}</Text> : null}
      {open && v.explanation ? (
        <Text style={{ color: p.text, fontSize: 13, marginTop: 6 }}>
          {/* a rule explains the rule, not the command: "Why it fired"; a model: "What it does" */}
          <Text style={{ color: p.muted }}>{t(isRuleVerdict(v) ? "feed.whyFired" : "feed.whatItDoes")}</Text>
          {sanitizeText(v.explanation)}
        </Text>
      ) : null}
      {open && v.goalFit ? (
        <Text style={{ color: p.text, fontSize: 13, marginTop: 6 }}>
          <Text style={{ color: p.muted }}>{t("feed.goalFit")}</Text>
          {sanitizeText(v.goalFit)}
        </Text>
      ) : null}
      {open ? <Text style={{ color: p.muted, fontSize: 11, marginTop: 4 }}>{srcText} · {t("fmt.seconds", { s: (v.latencyMs / 1000).toFixed(1) })}</Text> : null}
    </View>
  );
}

// ---------------------------------------------------------------------------
// Signed facts: command parts
// ---------------------------------------------------------------------------
/**
 * Sanitized text with the foreign letters of mixed runs highlighted (DISPLAY.md, section 3):
 * background, underline and the alphabet label next to them, `Sо⟨Cyr.⟩ns`. Goes inside the parent
 * Text.
 */
export function Marked({ text, runs, p }: { text: string; runs: MixedRun[] | undefined; p: Palette }) {
  const t = useT();
  const segs = markOdd(text, runs);
  if (segs.length === 1 && !segs[0].odd) return <>{text}</>;
  return (
    <>
      {segs.map((s, i) =>
        s.odd ? (
          <Text key={i}>
            <Text style={{ backgroundColor: p.riskMid, color: p.riskMidText, textDecorationLine: "underline" }}>{s.text}</Text>
            <Text style={{ color: p.riskMid, fontSize: 11, fontWeight: "700" }}>{`⟨${t(`script.short.${s.odd.script}` as MsgKey)}⟩`}</Text>
          </Text>
        ) : (
          <Text key={i}>{s.text}</Text>
        ),
      )}
    </>
  );
}

export function PartRow({ part, collapsed, p }: { part: Part; collapsed: boolean; p: Palette }) {
  const risky = part.danger.length > 0 || part.flags.length > 0;
  const sep = part.sep && part.sep !== "\n" ? `  ${part.sep}` : "";
  return (
    <View style={styles.partRow}>
      <View style={[styles.partBar, { backgroundColor: risky ? p.danger : p.border }]} />
      <Text
        style={[styles.mono, styles.partText, { color: risky ? p.danger : p.text, fontWeight: risky ? "700" : "400" }]}
        // a dangerous part is never truncated
        numberOfLines={collapsed && !risky ? 3 : undefined}
        selectable={!collapsed}
      >
        <Marked text={part.text} runs={part.mixed} p={p} />
        <Text style={{ color: p.muted, fontWeight: "400" }}>{sep}</Text>
      </Text>
    </View>
  );
}

export function PartsList({ view, open, onMore }: { view: CommandView; open: boolean; onMore: () => void }) {
  const p = usePalette();
  const t = useT();
  const shown = open ? view.parts.map((_, i) => i) : view.visible;
  // "{n} more" sits where parts are hidden: visible parts must not read as one continuous command
  const rows: ReactNode[] = [];
  let prev = -1;
  const gapChip = (n: number, key: string) => (
    <Pressable key={key} onPress={onMore} hitSlop={8} style={[styles.moreChip, { borderColor: p.border }]} accessibilityRole="button">
      <Text style={{ color: p.muted, fontSize: 12 }}>{t("feed.moreParts", { n })}</Text>
    </Pressable>
  );
  for (const i of shown) {
    if (i - prev > 1) rows.push(gapChip(i - prev - 1, `gap-${i}`));
    rows.push(<PartRow key={i} part={view.parts[i]} collapsed={!open} p={p} />);
    prev = i;
  }
  if (view.parts.length - 1 - prev > 0) rows.push(gapChip(view.parts.length - 1 - prev, "gap-end"));
  return (
    <View style={{ gap: 4 }}>
      {rows}
      {view.parts.length === 0 ? <Text style={[styles.mono, { color: p.muted }]}>(argv [])</Text> : null}
    </View>
  );
}

export function formLabel(t: ReturnType<typeof useT>, v: CommandView, hasArgv: boolean): string {
  if (v.form === "wrapper") return t("feed.form.wrapper");
  if (v.form === "shell" && v.shell) return t("feed.form.shell", { shell: v.shell });
  return hasArgv ? t("feed.form.argv") : t("feed.form.text");
}

/** Record type (formerly the EXEC / GATE / PLUGIN badge in the header): now in the second layer, under "Technical details" (V-41). */
export function typeLabel(card: Card, t: ReturnType<typeof useT>): string {
  if (card.kind === "exec") return "EXEC";
  if (card.kind === "gate") return card.gate?.exec ? t("feed.badge.execOs") : card.gate?.mode === "observe" ? t("feed.badge.gateObserve") : "GATE";
  return "PLUGIN";
}

/** Status on the right of the first line (V-01): "Dangerous", the rule or model verdict in words, "Not rated". */
export function StatusTag({ dangerous, v }: { dangerous: boolean; v: Verdict | "pending" | undefined }) {
  const p = usePalette();
  const t = useT();
  if (dangerous) {
    return (
      <Text style={[styles.status, { color: p.danger }]} testID="card-status">
        ⚠ {t("feed.danger.title")}
      </Text>
    );
  }
  if (!v) return null;
  if (v === "pending") return <Text style={[styles.status, { color: p.muted, fontWeight: "400" }]}>{t("feed.judgeThinking")}</Text>;
  if (isRuleVerdict(v)) return <Text style={[styles.status, { color: p.danger }]}>{t(v.source === "injection" ? "feed.chip.injection" : "feed.chip.blocklist")}</Text>;
  if (isUnrated(v)) return <Text style={[styles.status, { color: p.muted }]}>{t("feed.status.unrated")}</Text>;
  const risk = v.risk ?? 0;
  const tone = riskTone(risk);
  const color = tone === "low" ? p.riskLow : tone === "mid" ? p.riskMid : p.riskHigh;
  return <Text style={[styles.status, { color }]}>{t(tone === "low" ? "feed.chip.low" : tone === "mid" ? "feed.chip.mid" : "feed.chip.high", { risk })}</Text>;
}

// ---------------------------------------------------------------------------
// Expiry bar and consequences
// ---------------------------------------------------------------------------
export function TtlBar({ card, now, p }: { card: Card; now: number; p: Palette }) {
  if (!card.expiresAtMs) return null;
  const total = Math.max(1, card.expiresAtMs - card.createdAtMs);
  const left = Math.max(0, card.expiresAtMs - now);
  const frac = Math.min(1, left / total);
  return (
    <View style={[styles.ttlTrack, { backgroundColor: p.border }]} accessibilityLabel={formatTtl(card.expiresAtMs, now)}>
      <View style={{ width: `${frac * 100}%`, height: "100%", backgroundColor: left < TTL_URGENT_MS ? p.danger : p.accent, borderRadius: 2 }} />
    </View>
  );
}

/**
 * Program origin as reported by the server (meta.provenance, self-built category): file type,
 * libraries, network, the start of the hash and the start of the script. The script text was written
 * by the agent: display only, in monospace, invisible characters as labels; three lines in a
 * collapsed card.
 */
export function OriginFacts({ prov, open }: { prov: Provenance; open: boolean }) {
  const p = usePalette();
  const t = useT();
  const head = prov.head ? prov.head.split("\n").map(sanitizeText).join("\n") : null;
  return (
    <View style={styles.origin} testID="card-provenance">
      <Text style={[styles.meta, { color: p.muted, marginTop: 0 }]}>{t("feed.prov.title")}</Text>
      {provenanceFacts(prov).map((l, i) => (
        <Text key={i} style={[styles.meta, { color: p.text, marginTop: 2 }]}>
          • {l}
        </Text>
      ))}
      {head ? (
        <>
          <Text style={[styles.meta, { color: p.muted, marginTop: 4 }]}>{t("feed.prov.head")}</Text>
          <Text style={[styles.mono, styles.detailBlock, { color: p.text, fontSize: 12, marginTop: 2 }]} numberOfLines={open ? undefined : 3} selectable={open}>
            {head}
          </Text>
        </>
      ) : null}
    </View>
  );
}

/**
 * "Environment" (DISPLAY.md, section 7a): signed variables that change how the program behaves. A
 * collapsed card shows entries with a loader or flags and the rest as a count; an expanded one shows
 * all. Marks go before the name so a long value cannot hide them; the full value (up to 1024) when
 * expanded.
 */
export function EnvBlock({ env, open, onMore }: { env: EnvView; open: boolean; onMore: () => void }) {
  const p = usePalette();
  const t = useT();
  const shown = open ? env.entries : env.entries.filter((e) => e.loader || e.flags.length > 0);
  const hidden = env.entries.length - shown.length;
  return (
    <View style={{ marginTop: 6, gap: 2 }} testID="card-env">
      <Text style={[styles.meta, { color: p.muted, marginTop: 0 }]}>{t("envVars.title")}</Text>
      {shown.map((e, i) => {
        const tags = [...(e.loader ? [t("envVars.loader")] : []), ...e.flags.map((f) => t(`envVars.flag.${f}` as MsgKey))];
        return (
          <Text key={i} style={[styles.mono, { color: p.text, fontSize: 12 }]} numberOfLines={open ? undefined : 3} selectable={open} testID={e.loader ? "card-env-loader" : undefined}>
            {tags.length ? <Text style={{ color: p.danger, fontWeight: "700" }}>{`⚠ ${tags.join(", ")}: `}</Text> : null}
            {`${e.name}=${e.value}`}
            {e.cut ? <Text style={{ color: p.warn }}>{t("envVars.cut", { n: e.cut })}</Text> : null}
          </Text>
        );
      })}
      {hidden > 0 ? (
        <Pressable onPress={onMore} hitSlop={8} style={[styles.moreChip, { borderColor: p.border }]} accessibilityRole="button">
          <Text style={{ color: p.muted, fontSize: 12 }}>{t("envVars.more", { n: hidden })}</Text>
        </Pressable>
      ) : null}
    </View>
  );
}

/** Expanded signed facts block: full argv, exe, cwd, uid, process chain, host, expiry. */
export function ExpandedFacts({ card, now }: { card: Card; now: number }) {
  const p = usePalette();
  const t = useT();
  const exec = card.gate?.exec;
  if (!exec) {
    return (
      <View style={[styles.details, { borderColor: p.border }]}>
        {card.cwd ? <Line label="cwd: " value={sanitizeText(card.cwd)} /> : null}
        {card.host ? <Line label="host: " value={sanitizeText(card.host)} /> : null}
        {card.kind === "gate" && card.gate ? <Line label={t("feed.d.tool")} value={`${card.toolName ?? "-"}${card.gate.toolKind ? ` (${card.gate.toolKind})` : ""}`} /> : null}
        {card.kind === "plugin" ? <Line label={t("feed.d.pluginTool")} value={`${card.pluginId ?? "-"} / ${card.toolName ?? "-"}`} /> : null}
        {card.title && card.kind !== "exec" ? <Text style={[styles.detailLine, { color: p.text }]}>{sanitizeText(card.title)}</Text> : null}
        {card.description ? <Text style={[styles.detailLine, { color: p.text }]}>{sanitizeText(card.description)}</Text> : null}
        {card.args ? <Text style={[styles.mono, styles.detailBlock, { color: p.text }]} selectable>{sanitizeText(card.args)}</Text> : null}
      </View>
    );
  }
  return (
    <View style={[styles.details, { borderColor: p.border }]}>
      <Text style={[styles.detailLine, { color: p.muted }]}>{t("feed.fullArgv", { n: exec.argv.length })}</Text>
      {exec.argv.map((a, i) => (
        <Text key={i} style={[styles.mono, styles.detailBlock, { color: p.text }]} selectable>
          [{i}] <Marked text={sanitizeText(a)} runs={mixedRuns(a)} p={p} />
        </Text>
      ))}
      <Line label="exe: " value={sanitizeText(exec.exe)} runs={mixedRuns(exec.exe)} />
      <Line label="cwd: " value={sanitizeText(exec.cwd) || "-"} />
      <Line label="uid/gid: " value={`${exec.uid}/${exec.gid}`} />
      <Line label={t("feed.d.hostSupervisor")} value={`${sanitizeText(exec.host)} / ${exec.supervisorId.slice(0, 16)}`} />
      <Text style={[styles.detailLine, { color: p.muted }]}>{t("feed.d.chain")}</Text>
      {exec.chain.map((l, i) => (
        <Text key={`${l.pid}-${i}`} style={[styles.mono, { color: p.text, fontSize: 11 }]}>
          {"  ".repeat(i)}↑ {l.pid} <Marked text={sanitizeText(l.exe)} runs={mixedRuns(l.exe)} p={p} />
        </Text>
      ))}
      {card.expiresAtMs ? <Line label="" value={t("feed.ttlLeft", { ttl: formatTtl(card.expiresAtMs, now) })} /> : null}
      <Text style={[styles.detailLine, { color: p.muted }]}>{t("feed.envNotShown")}</Text>
    </View>
  );
}

/** meta from the transport: not covered by the digest, for information only. */
export function UnconfirmedMeta({ card, mentionHardware }: { card: Card; mentionHardware: boolean }) {
  const p = usePalette();
  const t = useT();
  const exec = card.gate?.exec;
  if (!exec) return null;
  const lines: string[] = [];
  if (exec.cls) lines.push(t("feed.metaClass", { cls: `${sanitizeText(exec.cls)}${exec.rule ? ` (${sanitizeText(exec.rule)})` : ""}` }));
  if (exec.category) lines.push(t("feed.metaCategory", { label: categoryLabel(exec.category), code: exec.category }));
  if (exec.detail) lines.push(t("feed.metaDetail", { detail: exec.detail }));
  if (exec.provenance?.sha256) lines.push(`sha256: ${exec.provenance.sha256}`);
  if (exec.provenance?.libs.length) lines.push(t("feed.prov.libs", { libs: exec.provenance.libs.map(sanitizeText).join(", ") }));
  if (exec.delegating) lines.push(t("feed.delegating", { what: sanitizeText(exec.delegating) }));
  if (exec.insideRoot) lines.push(t("feed.insideRoot", { pid: exec.insideRoot }));
  if (exec.hardware && mentionHardware) lines.push(t("feed.metaHw"));
  if (exec.judgeMeta) lines.push(t("feed.judgeMeta", { text: sanitizeText(exec.judgeMeta) }));
  if (!lines.length) return null;
  return (
    <View style={[styles.details, { borderColor: p.border }]}>
      <Text style={[styles.blockTitle, { color: p.muted, marginTop: 0 }]}>{t("feed.unconfirmed.title")}</Text>
      {lines.map((l, i) => (
        <Text key={i} style={[styles.detailLine, { color: p.muted }]}>
          {l}
        </Text>
      ))}
    </View>
  );
}

export function TechDetails({ card }: { card: Card }) {
  const p = usePalette();
  const t = useT();
  // line by line: formatting line breaks stay real, invisible characters inside lines become labels
  const payload = useMemo(() => (JSON.stringify(card.raw, null, 1) ?? "").split("\n").map(sanitizeText).join("\n"), [card.raw]);
  return (
    <View style={[styles.details, { borderColor: p.border }]}>
      <Text style={[styles.blockTitle, { color: p.muted, marginTop: 0 }]}>{t("feed.techDetails")}</Text>
      <Line label={t("feed.d.type")} value={typeLabel(card, t)} />
      <Line label="id: " value={card.id} />
      {card.gate ? <Line label="digest: " value={card.gate.digest} small /> : null}
      {card.gate?.exec ? <Line label="" value={t("feed.d.digest", { state: card.gate.exec.digestOk ? t("feed.d.digestOk") : t("feed.d.digestBad") })} /> : null}
      <Line label="agentId: " value={card.agentId ?? "-"} />
      <Line label="sessionKey: " value={card.sessionKey ?? "-"} />
      <Text style={[styles.detailLine, { color: p.muted }]}>payload:</Text>
      <Text style={[styles.mono, styles.detailBlock, { color: p.text, fontSize: 11 }]} selectable>
        {payload}
      </Text>
    </View>
  );
}

export function Line({ label, value, small, runs }: { label: string; value: string; small?: boolean; runs?: MixedRun[] }) {
  const p = usePalette();
  return (
    <Text style={[styles.detailLine, { color: p.muted }]}>
      {label}
      <Text style={[styles.mono, { color: p.text, fontSize: small ? 11 : 13 }]} selectable>
        {runs?.length ? <Marked text={value} runs={runs} p={p} /> : value}
      </Text>
    </Text>
  );
}
