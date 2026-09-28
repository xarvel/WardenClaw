// SPDX-License-Identifier: GPL-3.0-or-later
// setup-code from `openclaw qr --limited --setup-code-only` (or oc-pair://…): base64url(JSON{bootstrapToken,url}).
import { b64url, utf8Decode } from "./bytes";
import { t } from "./i18n";

export type SetupCode = { bootstrapToken: string; url: string };

export function decodeSetupCode(input: string): SetupCode {
  let code = input.trim();
  if (code.toLowerCase().startsWith("oc-pair://")) code = code.slice(10);
  let json: unknown;
  try {
    json = JSON.parse(utf8Decode(b64url.decode(code)));
  } catch {
    throw new Error(t("sc.parse"));
  }
  const obj = json as Record<string, unknown>;
  if (!obj || typeof obj.bootstrapToken !== "string" || !obj.bootstrapToken) {
    throw new Error(t("sc.noToken"));
  }
  return { bootstrapToken: obj.bootstrapToken, url: typeof obj.url === "string" ? obj.url : "" };
}
