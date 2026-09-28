// SPDX-License-Identifier: GPL-3.0-or-later
// What the empty feed and the offline banner say. The pill uses the same fault names.
import { t, type MsgKey } from "../../core/i18n";
import { explainProtocolError } from "../../core/protocolVersion";
import { linkFault, runCopy, type LinkFault, type RunCopy } from "../../core/serverMode";

export const FAULT_TITLE: Record<LinkFault, MsgKey> = {
  down: "wd.unavailable",
  revoked: "wd.fault.revoked",
  offline: "wd.fault.offline",
  protocol: "wd.fault.protocol",
};

const HINT_KEY: Record<RunCopy, MsgKey> = {
  observe: "feed.hint.observe",
  denylist: "feed.hint.denylist",
  tripwire: "feed.hint.tripwire",
  root: "feed.hint.root",
  ticket: "feed.hint.ticket",
};

export function faultBody(fault: LinkFault, lastError: string | null, host: string | null): string {
  switch (fault) {
    case "revoked":
      return t("notif.st.revokedText", { host: host || "wardend" });
    case "offline":
      return t("feed.hint.offline");
    case "protocol":
      return explainProtocolError(lastError)?.text ?? t("wd.fault.protocol");
    case "down":
      return t("feed.hint.unavailable");
  }
}

/** Empty feed. A connected wardend is described by its mode; "cards will appear" is only for the gateway adapter. */
export function emptyHint(status: string, mode: string | null, policy: string | null, reason: string | null, lastError: string | null, host: string | null, gatewayUp: boolean): string {
  if (status === "connected") {
    const copy = runCopy(mode, policy);
    return copy ? t(HINT_KEY[copy]) : t("wd.connected");
  }
  if (status === "awaiting-approval") return t("feed.hint.awaiting");
  const fault = linkFault(status, reason);
  if (fault) return faultBody(fault, lastError, host);
  if (gatewayUp) return t("feed.hint.connected");
  return t("feed.hint.unpaired");
}
