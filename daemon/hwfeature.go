// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"

	"github.com/xarvel/WardenClaw/daemon/feature"
)

// hwFeatureCheck: a build without the second factor (no hwkey tag) does not start with its
// settings. Silently dropped hardware_keys or require_hardware would leave the human sure that
// roots matching these rules are approved only with a key touch, while a single phone signature
// would approve them.
func hwFeatureCheck(keys, rules int) error {
	if feature.HWKey {
		return nil
	}
	if keys > 0 {
		return fmt.Errorf("config: hardware_keys (%d): %s; remove hardware_keys from the config", keys, feature.HWKeyOff)
	}
	if rules > 0 {
		return fmt.Errorf("policy: require_hardware (%d): %s; remove require_hardware from the policy, without the second factor these rules require nothing", rules, feature.HWKeyOff)
	}
	return nil
}

// hwStatus: second-factor fields for status and the journal start record: without the tag they are
// absent altogether.
func hwStatus(m map[string]any, keys any, rules int, info any) map[string]any {
	if feature.HWKey {
		m["hardwareKeys"], m["requireHardwareRules"] = keys, rules
		if info != nil {
			m["requireHardware"] = info
		}
	}
	return m
}
