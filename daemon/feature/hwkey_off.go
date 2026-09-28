// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !hwkey

package feature

// HWKey reports whether the second factor is compiled in: false without the hwkey tag (release).
const HWKey = false
