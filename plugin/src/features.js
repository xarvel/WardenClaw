// SPDX-License-Identifier: Apache-2.0
// Features not included in the release. One place for the whole plugin, like the hwkey build tag
// in wardend and wardenctl (daemon/docs/hwkey.md).

/**
 * Second factor (FIDO2 assertion YubiKey in the hw field of a decision). Not in the first release:
 * a decision with hw is rejected with hw_not_in_release rather than forwarded without it silently
 * (the user would think they approved with the key). To enable: return true; then hw is validated
 * by form and forwarded to wardend as-is.
 */
export const HARDWARE_KEY = false;
