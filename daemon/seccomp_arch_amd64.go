// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "golang.org/x/sys/unix"

// auditArch: the seccomp_data.arch value for the native system calls of this build.
// i386 (int 0x80) arrives with AUDIT_ARCH_I386 and gets ENOSYS, x32 is cut off in execFilter.
const auditArch = unix.AUDIT_ARCH_X86_64
