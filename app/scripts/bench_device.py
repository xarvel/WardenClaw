#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the Judge benchmark spike on a phone via adb (no UI).

  bench_device.py start <tag> "<query>"   deep link wardenclaw://bench?<query>, starts logcat + sampler in the background
  bench_device.py status <tag>            parse WARDEN_BENCH events (reassemble [i/n] chunks), crashes, memory/temperature peaks
  bench_device.py stop <tag>              stop background processes by PID (not pkill -f: would kill its own shell)

Files: /tmp/wb/<tag>.logcat, <tag>.samples.jsonl, <tag>.pids. After the done event the sampler exits and kills its logcat.
"""
import json, os, re, signal, subprocess, sys, time

PKG = "com.wardenclaw.app"
DIR = "/tmp/wb"
TAG_RE = re.compile(r"WARDEN_BENCH: (.*)$")
CHUNK_RE = re.compile(r"^\[(\d+)/(\d+)\](.*)$", re.S)
CRASH_RE = re.compile(r"FATAL EXCEPTION|Fatal signal|lowmemorykiller.*wardenclaw|Process %s .*has died|ANR in %s" % (re.escape(PKG), re.escape(PKG)))


def adb(*args, timeout=30):
    return subprocess.run(["adb", *args], capture_output=True, text=True, timeout=timeout).stdout


def paths(tag):
    os.makedirs(DIR, exist_ok=True)
    return {k: f"{DIR}/{tag}.{k}" for k in ("logcat", "samples.jsonl", "pids", "stop")}


def sample():
    out = adb("shell", f"dumpsys meminfo {PKG} | grep -E 'TOTAL PSS|TOTAL:' | head -1; "
              "dumpsys battery | grep -E ' temperature| level|AC powered|USB powered'; "
              "cat /sys/class/power_supply/battery/current_now; "
              "dumpsys thermalservice | sed -n '/Current temperatures from HAL/,/Current cooling/p' | "
              "grep -E 'mName=(VIRTUAL-SKIN|BIG|MID|LITTLE|battery),'; dumpsys thermalservice | grep -m1 'Thermal Status'; "
              "for c in 4 7; do echo cpu${c}max=$(cat /sys/devices/system/cpu/cpu$c/cpufreq/scaling_max_freq); done", timeout=40)
    s = {"t": round(time.time(), 1)}
    m = re.search(r"TOTAL PSS:\s*(\d+)", out) or re.search(r"TOTAL:\s*(\d+)", out)
    if m:
        s["pss_mb"] = round(int(m.group(1)) / 1024)
    m = re.search(r" temperature: (\d+)", out)
    if m:
        s["batt_c"] = int(m.group(1)) / 10
    m = re.search(r" level: (\d+)", out)
    if m:
        s["level"] = int(m.group(1))
    m = re.search(r"^(-?\d+)$", out, re.M)
    if m:
        s["cur_ma"] = round(int(m.group(1)) / 1000)
    for val, name in re.findall(r"mValue=([\d.]+), mType=-?\d+, mName=([\w-]+),", out):
        s[name.lower().replace("-", "_")] = round(float(val), 1)
    m = re.search(r"Thermal Status: (\d+)", out)
    if m:
        s["thermal"] = int(m.group(1))
    for c, khz in re.findall(r"cpu(\d)max=(\d+)", out):  # frequency cap: throttling visible before thermal status
        s[f"cpu{c}max_mhz"] = int(khz) // 1000
    s["ac"] = "AC powered: true" in out or "USB powered: true" in out
    return s


def parse_events(tag):
    p = paths(tag)
    events, crashes, parts = [], [], []
    if not os.path.exists(p["logcat"]):
        return events, crashes
    with open(p["logcat"], errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if CRASH_RE.search(line):
                crashes.append(line[-300:])
            m = TAG_RE.search(line)
            if not m:
                continue
            msg = m.group(1)
            c = CHUNK_RE.match(msg)
            if c:
                i, n, body = int(c.group(1)), int(c.group(2)), c.group(3)
                if i == 1:
                    parts = []
                parts.append(body)
                if i < n:
                    continue
                msg = "".join(parts)
                parts = []
            if msg.startswith("WARDEN_BENCH "):
                msg = msg[len("WARDEN_BENCH "):]
            try:
                events.append(json.loads(msg))
            except json.JSONDecodeError:
                events.append({"type": "unparsed", "raw": msg[:200]})
    return events, crashes


def cmd_start(tag, query):
    p = paths(tag)
    for k in ("logcat", "samples.jsonl", "stop"):
        if os.path.exists(p[k]):
            os.remove(p[k])
    adb("logcat", "-c")
    lc = subprocess.Popen(["adb", "logcat", "-v", "epoch", "-s", "WARDEN_BENCH:I", "AndroidRuntime:E", "DEBUG:F", "libc:F",
                           "ActivityManager:I", "lowmemorykiller:I", "ReactNativeJS:E"],
                          stdout=open(p["logcat"], "w"), stderr=subprocess.DEVNULL, start_new_session=True)
    sp = subprocess.Popen([sys.executable, os.path.abspath(__file__), "_sampler", tag],
                          stdout=subprocess.DEVNULL, stderr=open(f"{DIR}/{tag}.sampler.err", "w"), start_new_session=True)
    with open(p["pids"], "w") as fh:
        fh.write(f"{lc.pid} {sp.pid}\n")
    time.sleep(1)
    url = f"wardenclaw://bench?{query}"
    print(adb("shell", f"am start -a android.intent.action.VIEW -d '{url}' {PKG}").strip())
    print(f"started {tag}: logcat pid {lc.pid}, sampler pid {sp.pid}")


def cmd_sampler(tag):
    p = paths(tag)
    t_end = time.time() + 3 * 3600
    while time.time() < t_end and not os.path.exists(p["stop"]):
        try:
            s = sample()
            with open(p["samples.jsonl"], "a") as fh:
                fh.write(json.dumps(s) + "\n")
        except Exception as e:  # adb disconnected: log and continue
            with open(p["samples.jsonl"], "a") as fh:
                fh.write(json.dumps({"t": time.time(), "err": str(e)[:200]}) + "\n")
        ev, _ = parse_events(tag)
        if any(e.get("type") == "done" for e in ev):
            break
        time.sleep(10)
    # Kill our own logcat reader too: otherwise it would append to this file on the next run.
    time.sleep(2)
    try:
        os.killpg(int(open(p["pids"]).read().split()[0]), signal.SIGTERM)
    except (OSError, ValueError, IndexError):
        pass


def cmd_stop(tag):
    p = paths(tag)
    open(p["stop"], "w").close()
    if os.path.exists(p["pids"]):
        for pid in open(p["pids"]).read().split():
            try:
                os.killpg(int(pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
    print("stopped", tag)


def cmd_status(tag):
    p = paths(tag)
    if not os.path.exists(p["logcat"]):  # used to print RUNNING here, causing pass 4 to treat a non-started run as running
        print("NOT STARTED")
        return
    ev, crashes = parse_events(tag)
    cases = {}
    for e in ev:
        t = e.get("type")
        if t == "case":
            cases.setdefault(e["model"], []).append(e)
        elif t in ("log", "download", "url", "start", "status"):
            if t == "log":
                print("log:", e.get("msg"))
            elif t == "start":
                print("start:", json.dumps({k: e.get(k) for k in ("models", "opts", "cases")}))
            elif t == "status":
                print("status:", json.dumps({k: e.get(k) for k in ("downloaded", "freeMb")}))
            elif t == "download":
                print("download:", e)
    for model, cs in cases.items():
        bad = [c for c in cs if c.get("got") == "allow" and c.get("exp") != "allow"]
        print(f"cases {model}: {len(cs)} done, last {cs[-1]['id']} {cs[-1]['ms']} ms, unsafe allow so far {len(bad)}")
    for e in ev:
        if e.get("type") == "summary":
            b = e.get("battery") or {}
            keys = ("model", "n", "loadMs", "firstMs", "p50Ms", "p90Ms", "meanMs", "promptTps", "genTps", "meanPromptTokens",
                    "meanCachedTokens", "meanGenTokens", "accuracy", "acceptRate", "unsafeAllow", "overBlock", "layeredAccept",
                    "jsonValidPct", "errors", "error")
            print("SUMMARY", json.dumps({k: e.get(k) for k in keys}, ensure_ascii=False))
            print("  battery", json.dumps({k: b.get(k) for k in ("durationS", "deltaPct", "deltaMah", "avgCurrentMa", "idleCurrentMa",
                                                               "maxTempC", "maxThermalStatus", "plugged")}))
    if crashes:
        print("CRASH/DEATH lines:")
        for c in crashes[-8:]:
            print("  ", c)
    ss = []
    if os.path.exists(p["samples.jsonl"]):
        ss = [json.loads(l) for l in open(p["samples.jsonl"]) if l.strip()]
    if ss:
        def mx(k):
            v = [s[k] for s in ss if k in s]
            return max(v) if v else None
        def mn(k):
            v = [s[k] for s in ss if k in s]
            return min(v) if v else None
        print("samples:", len(ss), "| max pss_mb", mx("pss_mb"), "| max batt_c", mx("batt_c"), "| max skin", mx("virtual_skin"),
              "| max big", mx("big"), "| max thermal", mx("thermal"), "| min cpu4/cpu7 max MHz", mn("cpu4max_mhz"), mn("cpu7max_mhz"),
              "| last", json.dumps(ss[-1]))
    print("DONE" if any(e.get("type") == "done" for e in ev) else "RUNNING")


if __name__ == "__main__":
    cmd, tag = sys.argv[1], sys.argv[2]
    {"start": lambda: cmd_start(tag, sys.argv[3]), "status": lambda: cmd_status(tag), "stop": lambda: cmd_stop(tag),
     "_sampler": lambda: cmd_sampler(tag)}[cmd]()
