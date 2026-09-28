// SPDX-License-Identifier: GPL-3.0-or-later
import { Alert } from "react-native";
import { OwnerNotConfirmed } from "../core/controller";
import { errMsg } from "../core/errMsg";
import { t } from "../core/i18n";

/** Settings action error: "Not confirmed" (owner cancelled, nothing changed) or "Error". */
export function alertActionError(e: unknown) {
  if (e instanceof OwnerNotConfirmed) Alert.alert(t("owner.title"), e.message);
  else Alert.alert(t("common.error"), errMsg(e));
}
