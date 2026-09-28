// SPDX-License-Identifier: AGPL-3.0-or-later
// "Evil" process for the TOCTOU test: a second thread continuously rewrites the argv[1]
// buffer between "SAFE-ARG" and "EVIL-ARG" while the main thread calls execve("/bin/echo", [echo, buf]).
// The supervisor reads argv from memory at notification time; the kernel copies it again after
// CONTINUE. The thread can swap the value between those two moments.
//   cc -O1 -pthread -o evil_argv evil_argv.c
//   evil_argv        one attempt in this process (the bench)
//   evil_argv N      N attempts, each in a forked child (the test: every child's execve is a card
//                    of its own, while evil_argv itself is the supervised command)
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static char buf[16] = "SAFE-ARG";

static void *flip(void *arg) {
	(void)arg;
	volatile char *b = buf;
	for (;;) {
		b[0] = 'E'; b[1] = 'V'; b[2] = 'I'; b[3] = 'L';
		b[0] = 'S'; b[1] = 'A'; b[2] = 'F'; b[3] = 'E';
	}
	return NULL;
}

static int attempt(void) {
	pthread_t t;
	pthread_create(&t, NULL, flip, NULL);
	usleep(1000);
	char *argv[] = {"/bin/echo", buf, NULL};
	execve("/bin/echo", argv, environ);
	perror("execve");
	return 1;
}

int main(int argc, char **argv) {
	if (argc < 2)
		return attempt();
	int n = atoi(argv[1]);
	for (int i = 0; i < n; i++) {
		pid_t pid = fork();
		if (pid < 0) {
			perror("fork");
			return 1;
		}
		if (pid == 0)
			_exit(attempt());
		int st;
		waitpid(pid, &st, 0);
	}
	return 0;
}
