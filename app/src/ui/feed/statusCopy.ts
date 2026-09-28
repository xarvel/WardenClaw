// SPDX-License-Identifier: GPL-3.0-or-later
// What the empty feed and the offline banner say. The pill uses the same fault names.
import { t, type MsgKey } from "../../core/i18n";
import type { AppMode } from "../../core/decide";
import { explainProtocolError } from "../../core/protocolVersion";
import { linkFault, type LinkFault } from "../../core/serverMode";

export const FAULT_TITLE: Record<LinkFault, MsgKey> = {
  down: "wd.unavailable",
  revoked: "wd.fault.revoked",
  offline: "wd.fault.offline",
  protocol: "wd.fault.protocol",
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

/** Empty feed. A connected wardend sends every launch here; what happens to it depends on the app mode. */
export function emptyHint(status: string, mode: AppMode, reason: string | null, lastError: string | null, host: string | null): string {
  if (status === "connected") return t(mode === "observe" ? "feed.hint.observe" : mode === "delegate" ? "feed.hint.delegate" : "feed.hint.connected");
  if (status === "awaiting-approval") return t("feed.hint.awaiting");
  const fault = linkFault(status, reason);
  if (fault) return faultBody(fault, lastError, host);
  return t("feed.hint.unpaired");
}
