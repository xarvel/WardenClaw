# SPDX-License-Identifier: AGPL-3.0-or-later
import os, signal, sys, time
signal.signal(signal.SIGUSR1, lambda *a: print("child: SIGUSR1 handler ran", flush=True))
pid = os.fork()
if pid == 0:
    t=time.time()
    try:
        os.execv("/bin/true", ["/bin/true"])
    except OSError as e:
        print(f"child: execv failed after {time.time()-t:.1f}s: {e}", flush=True)
    os._exit(0)
for i in range(3):
    time.sleep(1); os.kill(pid, signal.SIGUSR1); print("parent: sent SIGUSR1", flush=True)
os.waitpid(pid, 0)
