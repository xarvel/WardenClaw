// SPDX-License-Identifier: GPL-3.0-or-later
// One approval card: signed facts, why it asks, and Allow / Deny.
import { useEffect, useRef, useState } from "react";
import { Alert, Animated, Easing, Pressable, StyleSheet, Text, View } from "react-native";
import * as Haptics from "expo-haptics";
import { Badge, BigButton, formatTtl } from "../components";
import { usePalette } from "../theme";
import { useT } from "../i18n";
import { Card, agentOf, categoryHint, clip, whyAsks } from "../../core/approvals";
import { useAppState } from "../../core/store";
import { HardwareRequired, OwnerNotConfirmed, hardwareRequirement, resolveCard, showSnack } from "../../core/controller";
import { errMsg } from "../../core/errMsg";
import { scoreRuleState } from "../../core/hardware";
import { cardSafety } from "../../core/safety";
import { mixedRuns, sanitizeText } from "../../core/display";
import { styles } from "./styles";
import { LEAVE_MS, TTL_URGENT_MS } from "./timing";
import { HoldButton } from "./HoldButton";
import { AssessmentChip, AssessmentDetails, EnvBlock, ExpandedFacts, Marked, OriginFacts, PartsList, StatusTag, TechDetails, TtlBar, UnconfirmedMeta, formLabel } from "./cardParts";

// YubiKey and the on-phone judge stay out of the release bundle unless the build flag is on.
const hardwareUi: typeof import("../Hardware") | null = process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_HARDWARE_KEY === "1" ? require("../Hardware") : null;
const opinionUi: typeof import("../LocalOpinion") | null = process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_PHONE_JUDGE === "1" ? require("../LocalOpinion") : null;

/** Buttons of a shifted card are disabled until `until`: the next card must not land under the finger. */
function useGuard(until: number): boolean {
  const [, force] = useState(0);
  useEffect(() => {
    const d = until - Date.now();
    if (d <= 0) return;
    const tm = setTimeout(() => force((x) => x + 1), d + 10);
    return () => clearTimeout(tm);
  }, [until]);
  return Date.now() < until;
}

// ---------------------------------------------------------------------------
// Card
// ---------------------------------------------------------------------------
export function CardView({ card, now, focused, leaving, guardUntil, offline }: { card: Card; now: number; focused?: boolean; leaving: boolean; guardUntil: number; offline: boolean }) {
  const p = usePalette();
  const t = useT();
  const verdict = useAppState((s) => s.verdicts[card.id]);
  const [open, setOpen] = useState(!!focused);
  useEffect(() => {
    if (focused) setOpen(true);
  }, [focused]);
  const [busy, setBusy] = useState<null | "allow-once" | "deny">(null);
  const [tap, setTap] = useState(false);
  // hint on an early hold release, 2 s
  const [holdTip, setHoldTip] = useState(false);
  const tipTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const showHoldTip = () => {
    setHoldTip(true);
    if (tipTimer.current) clearTimeout(tipTimer.current);
    tipTimer.current = setTimeout(() => setHoldTip(false), 2000);
  };
  useEffect(
    () => () => {
      if (tipTimer.current) clearTimeout(tipTimer.current);
    },
    [],
  );
  // verdict in the dependencies: a wardend score rule fires on the judge's score
  const hw = hardwareRequirement(card);
  // a YubiKey score rule stays silent without a signed score: this must be visible (L9)
  const scoreRule = scoreRuleState(card.gate?.exec?.hardware ?? null, hw.risk, verdict === "pending");
  const safety = cardSafety(card, verdict);
  const guarded = useGuard(guardUntil);
  const exec = card.gate?.exec ?? null;
  const view = card.view ?? null;
  const headline = view && view.headline !== null ? view.parts[view.headline].text : card.summary;

  // card leaving: opacity and height shrink, the neighbours slide in smoothly
  const height = useRef<number | null>(null);
  const anim = useRef(new Animated.Value(1)).current;
  useEffect(() => {
    if (leaving) Animated.timing(anim, { toValue: 0, duration: LEAVE_MS, easing: Easing.out(Easing.quad), useNativeDriver: false }).start();
  }, [leaving, anim]);

  const decided = (decision: "allow-once" | "deny", mock: boolean) => {
    const what = clip(headline, 60);
    showSnack(t(decision === "deny" ? "feed.snack.denied" : "feed.snack.allowed", { what }) + (mock ? t("feed.snack.mock") : ""), decision === "deny" ? "deny" : "allow");
    if (decision === "deny") Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium).catch(() => {});
    else Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => {});
  };

  const act = async (decision: "allow-once" | "deny") => {
    if (busy || leaving || offline) return;
    if (decision === "allow-once" && hw.need) return hardwareUi ? setTap(true) : undefined;
    setBusy(decision);
    try {
      const r = await resolveCard(card, decision);
      if (!r.applied && r.status.startsWith("mock")) return decided(decision, true); // dev mock: not sent anywhere
      if (r.applied) return decided(decision, false);
      if (r.retry) Alert.alert(t("feed.wardendRejected"), r.status);
      else Alert.alert(t("feed.alreadyDecided"), t("feed.alreadyDecidedBody", { status: r.status }));
    } catch (e) {
      if (e instanceof HardwareRequired) return hardwareUi ? setTap(true) : Alert.alert(t("feed.sendFailed"), t("feed.hwUnsupported"));
      if (e instanceof OwnerNotConfirmed) return showSnack(e.message, "info");
      Alert.alert(t("feed.sendFailed"), errMsg(e));
    } finally {
      setBusy(null);
    }
  };

  const disabled = busy !== null || guarded || leaving || offline;
  // build without YubiKey: a card the server lets through only with the key cannot be allowed here
  const allowDisabled = disabled || (hw.need && !hardwareUi);
  const borderColor = safety.dangerous ? p.danger : p.border;
  const factsTitle = exec ? t("feed.facts.title") : card.kind === "exec" || card.command ? t("feed.facts.gateway") : t("feed.facts.title");
  // First layer (V-01, IA-28): server and agent, status on the right; below, "Why it asks" by the
  // server category and the program origin facts. EXEC and digest in the second layer ("Technical
  // details").
  const server = card.host ?? exec?.host ?? null;
  const agent = agentOf(card);
  const why = whyAsks(exec);
  const whyHint = categoryHint(exec?.category ?? null);
  const prov = exec?.provenance ?? null;
  const header = [exec?.cwd ?? card.cwd, view ? formLabel(t, view, !!exec) : null].filter(Boolean).map((x) => sanitizeText(String(x))).join("  ·  ");

  const body = (
    <View
      style={[styles.card, { backgroundColor: p.card, borderColor, borderWidth: safety.dangerous ? 2 : StyleSheet.hairlineWidth }]}
      onLayout={(e) => {
        if (!leaving) height.current = e.nativeEvent.layout.height;
      }}
      testID={safety.dangerous ? "card-dangerous" : "card"}
    >
      <TtlBar card={card} now={now} p={p} />
      {safety.dangerous ? (
        <View style={[styles.danger, { backgroundColor: p.dangerBg, borderColor: p.danger }]} accessibilityRole="alert">
          {exec?.rootExec ? (
            <Text style={{ color: p.danger, fontWeight: "900", fontSize: 16, marginBottom: 2 }} testID="card-rootexec">
              ⛔ {t("feed.rootExec.title")}
            </Text>
          ) : null}
          <Text style={{ color: p.danger, fontWeight: "800", fontSize: 14 }}>⚠ {t("feed.danger.title")}</Text>
          {(open ? safety.reasons : safety.reasons.slice(0, 3)).map((r, i) => (
            <Text key={i} style={{ color: p.text, fontSize: 13, marginTop: 2 }}>
              • {r}
            </Text>
          ))}
          {!open && safety.reasons.length > 3 ? <Text style={{ color: p.muted, fontSize: 12, marginTop: 2 }}>+{safety.reasons.length - 3}</Text> : null}
        </View>
      ) : null}

      <Pressable onPress={() => setOpen((v) => !v)} accessibilityRole="button" accessibilityState={{ expanded: open }}>
        <View style={styles.row}>
          <View style={styles.who}>
            {card.mock ? <Badge text={t("feed.badge.test")} bg={p.riskMid} color={p.riskMidText} /> : null}
            <Text style={[styles.server, { color: p.text }]} numberOfLines={1} testID="card-server">
              {server ? sanitizeText(server) : t("feed.hostGateway")}
              {agent ? <Text style={[styles.agent, { color: p.muted }]}>{`  ·  ${agent}`}</Text> : null}
            </Text>
          </View>
          <StatusTag dangerous={safety.dangerous} v={verdict} />
        </View>
        {why ? (
          <View style={styles.why} testID="card-why">
            <Text style={[styles.whyText, { color: p.text }]}>{t("feed.whyAsks", { why })}</Text>
            {whyHint ? <Text style={[styles.meta, { color: p.muted, marginTop: 2 }]}>{whyHint}</Text> : null}
            {open ? <Text style={[styles.meta, { color: p.muted, marginTop: 2 }]}>{t("feed.whyServerNote")}</Text> : null}
          </View>
        ) : null}
        {prov ? <OriginFacts prov={prov} open={open} /> : null}

        {card.mock ? <Text style={[styles.meta, { color: p.warn, fontWeight: "700" }]}>{t("feed.testCard")}</Text> : null}

        {/* Block 1: signed facts; a digest match is in the second layer, a mismatch is visible at once */}
        <Text style={[styles.blockTitle, { color: p.muted }]}>
          {factsTitle}
          {exec && !exec.digestOk ? <Text style={{ color: p.danger }}>{`  ·  ${t("feed.d.digest", { state: t("feed.d.digestBad") })}`}</Text> : null}
        </Text>
        {header ? (
          <Text style={[styles.meta, { color: p.muted }]} numberOfLines={open ? undefined : 1}>
            {header}
          </Text>
        ) : null}
        {view ? (
          <PartsList view={view} open={open} onMore={() => setOpen(true)} />
        ) : (
          <Text style={[styles.summary, { color: p.text }]} numberOfLines={open ? undefined : 3}>
            {card.kind === "gate" ? t("feed.prefix.signTool", { tool: card.toolName ?? t("feed.toolCall") }) : t("feed.prefix.plugin")}
            <Text style={styles.mono}>{card.summary}</Text>
          </Text>
        )}
        {exec ? (
          <Text style={[styles.meta, { color: p.muted }]} numberOfLines={open ? undefined : 1}>
            <Marked text={sanitizeText(exec.exe)} runs={mixedRuns(exec.exe)} p={p} />
            {`  ·  uid ${exec.uid}`}
            {exec.uid === 0 ? " (root)" : ""}
          </Text>
        ) : null}
        {exec?.envView?.entries.length ? <EnvBlock env={exec.envView} open={open} onMore={() => setOpen(true)} /> : null}
        {open ? <ExpandedFacts card={card} now={now} /> : null}

        {/* Consequences */}
        {card.expiresAtMs ? (
          <Text style={[styles.consequence, { color: card.expiresAtMs - now < TTL_URGENT_MS ? p.danger : p.text }]}>
            {card.expiresAtMs > now ? t("feed.noAnswer", { ttl: formatTtl(card.expiresAtMs, now) }) : t("feed.noAnswerSoon")}
          </Text>
        ) : null}
        {safety.root ? <Text style={[styles.consequence, { color: p.warn }]}>{t("feed.coversAll")}</Text> : null}
        {open ? <Text style={[styles.consequence, { color: p.muted }]}>{t("feed.denyEffect")}</Text> : null}
        {hw.need ? (
          <Text style={[styles.meta, { color: p.warn, fontWeight: "700" }]}>{hardwareUi ? t("feed.hwOnly", { why: hw.why }) : t("feed.hwUnsupported")}</Text>
        ) : !hardwareUi ? null : scoreRule === "silent" ? (
          <Text style={[styles.meta, { color: p.warn }]} testID="hw-score-silent">{t("feed.hwScoreSilent", { score: exec?.hardware?.minScore ?? "?" })}</Text>
        ) : scoreRule !== "none" ? (
          <Text style={[styles.meta, { color: p.muted }]}>{t("feed.hwIfRisk", { score: exec?.hardware?.minScore ?? "?" })}</Text>
        ) : null}
        {card.kind === "gate" && !exec && card.gate?.mode === "observe" ? <Text style={[styles.meta, { color: p.warn }]}>{t("feed.gateObserving")}</Text> : null}

        {/* Block 2: assessment, not signed (rule or model) */}
        {verdict || open ? (
          <View style={[styles.assess, { borderColor: p.border }]}>
            <Text style={[styles.blockTitle, { color: p.muted, marginTop: 0 }]}>{t("feed.assess.title")}</Text>
            <AssessmentChip v={verdict} />
            <AssessmentDetails v={verdict} open={open} />
            {opinionUi ? <opinionUi.LocalOpinionBar cardId={card.id} open={open} /> : null}
          </View>
        ) : opinionUi ? (
          <opinionUi.LocalOpinionBar cardId={card.id} open={open} />
        ) : null}
        {open && exec ? <UnconfirmedMeta card={card} mentionHardware={!!hardwareUi} /> : null}
        {open ? <TechDetails card={card} /> : null}
        <Text style={[styles.hint, { color: p.muted }]}>{open ? t("feed.collapse") : t("feed.more")}</Text>
      </Pressable>

      {offline ? <Text style={[styles.meta, { color: p.warn, marginTop: 8 }]}>{t("feed.fault.offline")}</Text> : null}
      <View style={[styles.actions, { opacity: guarded || offline ? 0.45 : 1 }]}>
        {safety.dangerous ? (
          <>
            {/* on a dangerous card "Deny" comes first, in focus order too (ux-copy A-18) */}
            <BigButton title={busy === "deny" ? "…" : t("feed.deny")} color={p.deny} textColor={p.denyText} disabled={disabled} onPress={() => act("deny")} style={{ flex: 1.3 }} />
            <HoldButton title={hw.need && hardwareUi ? t("feed.allowHw") : t("feed.allow")} busy={busy === "allow-once"} disabled={allowDisabled} host={card.host ?? null} what={clip(headline, 120)} onConfirm={() => act("allow-once")} onEarly={showHoldTip} />
          </>
        ) : (
          <>
            <BigButton title={busy === "allow-once" ? "…" : hw.need && hardwareUi ? t("feed.allowHw") : t("feed.allow")} color={p.allow} textColor={p.allowText} disabled={allowDisabled} onPress={() => act("allow-once")} />
            <BigButton title={busy === "deny" ? "…" : t("feed.deny")} color={p.deny} textColor={p.denyText} disabled={disabled} onPress={() => act("deny")} />
          </>
        )}
      </View>
      {safety.dangerous && holdTip ? (
        <Text style={[styles.meta, { color: p.text, textAlign: "center" }]} accessibilityLiveRegion="polite" testID="hold-early">
          {t("feed.hold.early")}
        </Text>
      ) : null}
      {hardwareUi ? (
        <hardwareUi.HardwareTapModal
          card={tap ? card : null}
          why={hw.why}
          onClose={(applied) => {
            setTap(false);
            if (applied) decided("allow-once", applied === "mock");
          }}
        />
      ) : null}
    </View>
  );

  // the wrapper is always the same, so the card tree is not recreated
  const h = height.current ?? 0;
  return (
    <Animated.View
      pointerEvents={leaving ? "none" : "auto"}
      style={leaving && h > 0 ? { opacity: anim, height: anim.interpolate({ inputRange: [0, 1], outputRange: [0, h + 14] }), overflow: "hidden" } : leaving ? { opacity: anim } : undefined}
    >
      {body}
    </Animated.View>
  );
}
