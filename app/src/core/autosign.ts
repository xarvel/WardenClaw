// SPDX-License-Identifier: GPL-3.0-or-later
// Who signs a card without the owner, and when. wardend never decides on its own: every launch
// outside an approved tree waits for a signed ticket from the phone (fail-closed on its TTL). The
// modes therefore live only here:
//   manual   the owner signs every card;
//   delegate the judge (autopilot) allows below the threshold and denies on its own (decide.ts);
//   observe  the phone signs every card at once, no judge, no question: it only writes the journal.
// Outside every mode, a harness service launch (meta.class "service": the gateway's node workers,
// lsof, systemctl show, the claude-cli pack) is signed by rule unless the owner asked to see them.
// What no automatic signer may allow: a rootexec card (protocol/README.md 3a: root outside the
// gate), an envelope the phone did not recompute, a card the server wants a hardware key for.
// Pure module (no RN): the tests compile it.
import type { Card } from "./approvals";
import { autopilotAllowRefusal, gateAllowRefusal } from "./approvals";
import { autoDecision, type AppMode, type Verdict } from "./decide";
import { t } from "./i18n";

/** Who signed without the owner: the observe mode, the service rule, or the judge (autopilot). */
export type AutoSigner = "observe" | "service" | "judge";

export type AutoPlan =
  | { kind: "sign"; by: AutoSigner; decision: "allow-once" | "deny" }
  /** A rule would have signed, but may not: the owner decides, and the journal says why. */
  | { kind: "hold"; by: AutoSigner; why: string }
  /** Nothing automatic applies: the owner decides (manual mode, or the judge says ask). */
  | null;

export type AutoContext = {
  mode: AppMode;
  threshold: number;
  /** "Ask me about harness service launches too": the service rule is off. */
  askService: boolean;
  /** The server requires a hardware key for this card (hardwareRequirement): only the owner's hand signs it. */
  hwNeed: boolean;
  /** cardSafety(card).dangerous: rules, flags, loader, a failed envelope. */
  dangerous: boolean;
};

/** A harness service launch: wardend labelled the exec meta.class "service". A rootexec card is never one. */
export function isServiceLaunch(card: Card): boolean {
  const exec = card.gate?.exec;
  return !!exec && exec.cls === "service" && !exec.rootExec;
}

/**
 * Why no automatic signer may allow this card, null if one may: the phone did not recompute the
 * envelope (only a deny can be signed), it is a rootexec card (no automatic approver may allow it),
 * or the server requires a hardware key (the touch is the owner's). The loader rule
 * (autopilotAllowRefusal) is not here: it binds the judge, observe signs such a card and marks it.
 */
export function autoAllowRefusal(card: Card, hwNeed: boolean): string | null {
  const refusal = gateAllowRefusal(card);
  if (refusal) return refusal;
  if (card.gate?.exec?.rootExec) return t("rootExec.autopilotNo");
  if (hwNeed) return t("auto.hold.hardware");
  return null;
}

/**
 * The automatic decision for a card once its verdict is known. Order: observe signs everything it
 * may; the service rule signs a harness launch in every other mode unless the owner wants to see
 * them, and never a dangerous one; the judge decides only on autopilot. Mock cards are never signed.
 */
export function autoPlan(card: Card, v: Verdict, o: AutoContext): AutoPlan {
  if (card.mock) return null;
  const service = isServiceLaunch(card) && !o.askService;
  if (o.mode === "observe") {
    const by: AutoSigner = service ? "service" : "observe";
    const why = autoAllowRefusal(card, o.hwNeed);
    return why ? { kind: "hold", by, why } : { kind: "sign", by, decision: "allow-once" };
  }
  if (service) {
    // the class is server meta, not signed: a service launch that trips the local rules or flags goes to the owner
    if (o.dangerous) return { kind: "hold", by: "service", why: t("auto.hold.dangerousService") };
    const why = autoAllowRefusal(card, o.hwNeed);
    return why ? { kind: "hold", by: "service", why } : { kind: "sign", by: "service", decision: "allow-once" };
  }
  if (o.mode === "delegate") {
    const auto = autoDecision(v, o.threshold);
    if (!auto) return null;
    if (auto === "deny") return { kind: "sign", by: "judge", decision: "deny" };
    const why = autoAllowRefusal(card, o.hwNeed) ?? autopilotAllowRefusal(card);
    return why ? { kind: "hold", by: "judge", why } : { kind: "sign", by: "judge", decision: "allow-once" };
  }
  return null;
}

/** Observe and autopilot live this long, then the app drops back to manual by itself; enabling again extends. */
export const AUTO_MODE_TTL_MS = 60 * 60 * 1000;

/** The mode the app falls back to when a timed mode ends, the judge changes, or the judge escalates: manual, the owner. */
export const FALLBACK_MODE: AppMode = "manual";
