// SPDX-License-Identifier: AGPL-3.0-or-later
// Helper for the path-resolve bypass test: runs inside the gate, enters its own user+mount
// namespace via unshare(2) (without the delegating binaries unshare/nsenter that the gate
// would see), then execve the target. wardend resolves the path in ITS OWN mount ns, but the
// kernel executes it in the child's ns. That gap should now produce a card, not a silent logged.
//   cc -O1 -o nsexec nsexec.c
#define _GNU_SOURCE
#include <sched.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void wf(const char *path, const char *val) {
	int fd = open(path, O_WRONLY);
	if (fd < 0)
		return;
	if (write(fd, val, strlen(val)) < 0) {
		/* without writing the map the process stays nobody in the new ns; irrelevant for the test */
	}
	close(fd);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "usage: nsexec PROG [args...]\n");
		return 2;
	}
	uid_t uid = geteuid();
	gid_t gid = getegid();
	if (unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0) {
		perror("unshare");
		return 3; // kernel without unprivileged userns: test is skipped
	}
	char buf[64];
	wf("/proc/self/setgroups", "deny");
	snprintf(buf, sizeof buf, "%d %d 1", (int)uid, (int)uid);
	wf("/proc/self/uid_map", buf);
	snprintf(buf, sizeof buf, "%d %d 1", (int)gid, (int)gid);
	wf("/proc/self/gid_map", buf);
	execv(argv[1], &argv[1]);
	perror("execv");
	return 4;
}
