// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "golang.org/x/sys/unix"

// auditArch: the seccomp_data.arch value for the native system calls of this build.
const auditArch = unix.AUDIT_ARCH_AARCH64
