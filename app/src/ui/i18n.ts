// SPDX-License-Identifier: GPL-3.0-or-later
// Localization hook for components: re-render on language change, t() from src/core/i18n.
import { useSyncExternalStore } from "react";
import { getLang, subscribeLang, t } from "../core/i18n";

export function useT(): typeof t {
  useSyncExternalStore(subscribeLang, getLang, getLang);
  return t;
}
