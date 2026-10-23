"""Compare confined gvx ARM64 with an existing WSL2 distribution."""

import argparse
import concurrent.futures
from contextlib import closing
import ctypes
from ctypes import wintypes as w
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import platform
import queue
import socket
import statistics
import subprocess
import threading
import time
import uuid


class MemoryStatus(ctypes.Structure):
    _fields_ = [("length", w.DWORD), ("load", w.DWORD)] + [
        (name, ctypes.c_ulonglong)
        for name in ("total_physical", "available_physical", "total_page", "available_page",
                     "total_virtual", "available_virtual", "extended_virtual")
    ]


class PerformanceInfo(ctypes.Structure):
    _fields_ = [("size", w.DWORD)] + [
        (name, ctypes.c_size_t)
        for name in ("commit", "commit_limit", "commit_peak", "physical_total", "physical_available",
                     "system_cache", "kernel_total", "kernel_paged", "kernel_nonpaged", "page_size")
    ] + [("handles", w.DWORD), ("processes", w.DWORD), ("threads", w.DWORD)]


class ProcessEntry(ctypes.Structure):
    _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("pid", w.DWORD),
                ("heap", ctypes.c_size_t), ("module", w.DWORD), ("threads", w.DWORD),
                ("parent", w.DWORD), ("priority", w.LONG), ("flags", w.DWORD),
                ("name", w.WCHAR * 260)]


class ProcessMemory(ctypes.Structure):
    _fields_ = [("size", w.DWORD), ("faults", w.DWORD)] + [
        (name, ctypes.c_size_t)
        for name in ("peak_ws", "ws", "peak_paged", "paged", "peak_nonpaged", "nonpaged",
                     "pagefile", "peak_pagefile", "private_commit")
    ]


kernel = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
kernel.CreateToolhelp32Snapshot.restype = w.HANDLE
kernel.OpenProcess.restype = w.HANDLE
kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
kernel.CloseHandle.argtypes = [w.HANDLE]
kernel.Process32FirstW.argtypes = [w.HANDLE, ctypes.POINTER(ProcessEntry)]
kernel.Process32NextW.argtypes = [w.HANDLE, ctypes.POINTER(ProcessEntry)]
kernel.GetProcessTimes.argtypes = [w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4
psapi.GetProcessMemoryInfo.argtypes = [w.HANDLE, ctypes.POINTER(ProcessMemory), w.DWORD]


def processes():
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    entries = []
    try:
        entry = ProcessEntry(size=ctypes.sizeof(ProcessEntry))
        success = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while success:
            entries.append((entry.pid, entry.parent, entry.name))
            success = kernel.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    return entries


def process_metrics(pid):
    handle = kernel.OpenProcess(0x410, False, pid)
    if not handle:
        return {"pid": pid, "error": ctypes.get_last_error()}
    try:
        memory = ProcessMemory(size=ctypes.sizeof(ProcessMemory))
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.size):
            return {"pid": pid, "error": ctypes.get_last_error()}
        times = [w.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
            raise ctypes.WinError(ctypes.get_last_error())
        cpu = sum((t.dwHighDateTime << 32) | t.dwLowDateTime for t in times[2:]) / 10_000_000
        return {"pid": pid, "working_set_bytes": memory.ws,
                "private_commit_bytes": memory.private_commit, "cpu_seconds": cpu,
                "created_ticks": (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime}
    finally:
        kernel.CloseHandle(handle)


def owned_process_metrics(entries, roots, read_metrics):
    owned = set(roots)
    metrics = {pid: read_metrics(pid) for pid in owned}
    excluded = {}
    while True:
        children = set()
        for pid, parent, _ in entries:
            if parent not in owned or pid in owned:
                continue
            if pid not in metrics:
                metrics[pid] = read_metrics(pid)
            child = metrics[pid]
            parent_created = metrics[parent].get("created_ticks")
            child_created = child.get("created_ticks")
            if parent_created is None or child_created is None:
                excluded[pid] = child
                continue
            # Windows can reuse the PID of a parent that has already exited.
            if child_created >= parent_created:
                children.add(pid)
        if not children:
            break
        owned |= children
    names = {pid: {"name": name, "parent": parent} for pid, parent, name in entries}
    return ([metrics[pid] | names.get(pid, {}) for pid in sorted(owned)], list(excluded.values()))


def memory_snapshot(roots):
    memory = MemoryStatus(length=ctypes.sizeof(MemoryStatus))
    info = PerformanceInfo(size=ctypes.sizeof(PerformanceInfo))
    if not kernel.GlobalMemoryStatusEx(ctypes.byref(memory)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not psapi.GetPerformanceInfo(ctypes.byref(info), info.size):
        raise ctypes.WinError(ctypes.get_last_error())
    entries = processes()
    owned, excluded = owned_process_metrics(entries, roots, process_metrics)
    return {"time": time.time(), "available_physical_bytes": memory.available_physical,
            "host_commit_bytes": info.commit * info.page_size,
            "owned_processes": owned,
            "excluded_processes": excluded,
            "wsl_vm": [process_metrics(pid) for pid, _, name in entries if name.lower() == "vmmemwsl"]}


def run(command, **kwargs):
    return subprocess.run(command, check=True, creationflags=subprocess.CREATE_NO_WINDOW, **kwargs)


def wsl_vm_cim():
    script = "Get-CimInstance Win32_Process -Filter \"Name='vmmemWSL'\" | Select-Object ProcessId,WorkingSetSize,PageFileUsage | ConvertTo-Json -Compress"
    return json.loads(run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, timeout=30).stdout)


def distribution(values):
    ordered = sorted(values)
    return {"count": len(values), "median": statistics.median(values),
            "p95": ordered[math.ceil(len(values) * .95) - 1], "min": ordered[0], "max": ordered[-1]}


def summarize(results):
    summary = {"metadata": results["metadata"], "startup_ms": {}, "compute_ms": {},
               "idle": [], "http": {}, "failures": results["failures"]}
    for engine in ("gvx", "wsl"):
        startup = [row["elapsed_ms"] for row in results["startup"] if row["engine"] == engine]
        if startup:
            summary["startup_ms"][engine] = distribution(startup)
        summary["compute_ms"][engine] = {}
        for mode in ("cpu", "syscall"):
            values = [row["elapsed_ns"] / 1e6 for row in results["compute"]
                      if row["engine"] == engine and row["mode"] == mode]
            if values:
                summary["compute_ms"][engine][mode] = distribution(values)
        requests = [row for row in results["http"] if row["engine"] == engine]
        if requests:
            summary["http"][engine] = {
                "requests_per_second": distribution([len(row["latencies_ms"]) / row["elapsed_seconds"] for row in requests]),
                "latency_ms": distribution([value for row in requests for value in row["latencies_ms"]]),
                "errors": sum(len(row["errors"]) for row in requests)}
    for row in results["idle"]:
        baseline = row["baseline"]
        samples = row["samples"]
        physical_baseline = statistics.median(sample["available_physical_bytes"] for sample in baseline)
        commit_baseline = statistics.median(sample["host_commit_bytes"] for sample in baseline)
        first_cpu = {p["pid"]: p for p in samples[0]["owned_processes"]}
        cpu_delta = sum(p["cpu_seconds"] - first_cpu[p["pid"]]["cpu_seconds"]
                        for p in samples[-1]["owned_processes"] if p["pid"] in first_cpu)
        summary["idle"].append({
            "engine": row["engine"], "instances": row["instances"],
            "seconds": samples[-1]["time"] - samples[0]["time"],
            "host_physical_delta_bytes": distribution([physical_baseline - s["available_physical_bytes"] for s in samples]),
            "host_commit_delta_bytes": distribution([s["host_commit_bytes"] - commit_baseline for s in samples]),
            "owned_private_commit_bytes": distribution([sum(p.get("private_commit_bytes", 0) for p in s["owned_processes"]) for s in samples]),
            "owned_process_count": distribution([len(s["owned_processes"]) for s in samples]),
            "owned_cpu_seconds": cpu_delta,
            "wsl_vm_before_cim": row["wsl_vm_before_cim"],
            "wsl_vm_after_cim": row["wsl_vm_after_cim"]})
    return summary


class Guest:
    def __init__(self, command, log):
        self.stderr = log.open("wb")
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.stderr, creationflags=subprocess.CREATE_NO_WINDOW)
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self.read_lines, daemon=True)
        self.reader.start()

    def read_lines(self):
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put(b"")

    def ready(self):
        line = self.lines.get(timeout=60)
        value = json.loads(line)
        if value.get("ready") is not True:
            raise RuntimeError(f"Guest did not report readiness: {value}")

    def close(self):
        try:
            self.process.stdin.close()
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)
            raise RuntimeError("Owned guest did not stop after stdin closed")
        finally:
            self.reader.join(timeout=5)
            self.process.stdout.close()
            self.stderr.close()
        if self.process.returncode:
            raise RuntimeError(f"Guest exited with status {self.process.returncode}")


def close_guests(guests):
    errors = []
    for guest in reversed(guests):
        try:
            guest.close()
        except Exception as error:
            errors.append(error)
    if errors:
        raise ExceptionGroup("Owned guests failed to stop", errors)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def http_request(connection):
    start = time.perf_counter()
    connection.request("GET", "/")
    response = connection.getresponse()
    body = response.read()
    if response.status != 200 or body != b"a" * 1024:
        raise RuntimeError("HTTP status or payload differs")
    return (time.perf_counter() - start) * 1000


def http_worker(port, count):
    latencies = []
    errors = []
    with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=5)) as connection:
        for _ in range(count):
            try:
                latencies.append(http_request(connection))
            except (OSError, http.client.HTTPException, RuntimeError) as error:
                errors.append(str(error))
                connection.close()
    return latencies, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--distribution", default="Debian")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--idle-seconds", type=float, default=60)
    parser.add_argument("--counts", type=int, nargs="+", default=[1, 4, 16])
    parser.add_argument("--http-requests", type=int, default=2000)
    parser.add_argument("--phases", nargs="+", choices=["startup", "compute", "idle", "http"],
                        default=["startup", "compute", "idle", "http"])
    args = parser.parse_args()
    if args.samples < 1 or args.idle_seconds <= 0 or any(n < 1 or n > 16 for n in args.counts):
        parser.error("samples, idle-seconds, or counts outside the supported range")
    if args.http_requests < 4 or args.http_requests % 4:
        parser.error("http-requests must be a positive multiple of four")
    repo = Path(__file__).resolve().parents[2]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    guest_binary = output / "guest.elf"
    runner = output / "rungv.exe"
    env = dict(os.environ, GOOS="linux", GOARCH="arm64", CGO_ENABLED="0")
    run(["go", "build", "-o", str(guest_binary), "./internal/benchguest"], cwd=repo, env=env)
    run(["go", "build", "-o", str(runner), "./cmd/rungv"], cwd=repo)
    wsl = ["wsl.exe", "-d", args.distribution, "--exec"]
    linux_dir = f"/tmp/gvx-bench-{uuid.uuid4().hex}"
    linux_binary = linux_dir + "/guest"
    run(wsl + ["mkdir", "-m", "700", linux_dir])
    run(wsl + ["sh", "-c", f"cat > {linux_binary} && chmod 700 {linux_binary}"], input=guest_binary.read_bytes())
    digest = hashlib.sha256(guest_binary.read_bytes()).hexdigest()
    installed_digest = run(wsl + ["sha256sum", linux_binary], capture_output=True).stdout.decode().split()[0]
    if installed_digest != digest:
        raise RuntimeError("WSL workload digest differs")
    results = {"metadata": {"revision": run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True).stdout.decode().strip(),
                             "diff": run(["git", "status", "--short"], cwd=repo, capture_output=True).stdout.decode(),
                             "host": platform.platform(), "processor": platform.processor(),
                             "go": run(["go", "version"], capture_output=True).stdout.decode().strip(),
                             "wsl_kernel": run(wsl + ["uname", "-r"], capture_output=True).stdout.decode().strip(),
                             "guest_sha256": digest, "runner_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
                             "wsl_distribution": args.distribution, "wsl_state": "kept running; no shutdown",
                             "settings": vars(args) | {"output": str(output)}},
               "startup": [], "compute": [], "idle": [], "http": [], "failures": []}
    results["metadata"]["wsl_vm_initial_cim"] = wsl_vm_cim()
    sequence = 0

    def save():
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    def command(engine, mode, *extra, port=None):
        workload = [f"-mode={mode}", *extra]
        if port:
            workload.append(f"-port={port if engine == 'wsl' else 8080}")
        if engine == "wsl":
            return wsl + [linux_binary, *workload]
        network = ["-net=nat", "-p", f"127.0.0.1:{port}:8080"] if port else ["-net=none"]
        return [str(runner), "run", "-platform=systrap", *network,
                f"-cache-dir={output / 'cache'}", f"-bin={guest_binary}", "--", *workload]

    def start_guest(engine, mode, port=None):
        nonlocal sequence
        sequence += 1
        guest = Guest(command(engine, mode, port=port), output / f"{engine}-{mode}-{sequence}.log")
        try:
            guest.ready()
        except BaseException:
            guest.close()
            raise
        return guest

    try:
        for engine in ("gvx", "wsl"):
            warm = run(command(engine, "hello"), capture_output=True, timeout=60)
            if json.loads(warm.stdout) != {"arch": "arm64", "mode": "hello"}:
                raise RuntimeError("Warm-up output differs")
        print("Warm-up complete", flush=True)
        for sample in range(args.samples if "startup" in args.phases else 0):
            for engine in (("gvx", "wsl") if sample % 2 == 0 else ("wsl", "gvx")):
                start = time.perf_counter()
                completed = run(command(engine, "hello"), capture_output=True, timeout=60)
                elapsed = (time.perf_counter() - start) * 1000
                if json.loads(completed.stdout) != {"arch": "arm64", "mode": "hello"}:
                    raise RuntimeError("Startup output differs")
                results["startup"].append({"engine": engine, "sample": sample, "elapsed_ms": elapsed})
            save()
        if "startup" in args.phases:
            print("Startup complete", flush=True)
        cpu_checksum = None
        for mode, count in ((("cpu", 100_000_000), ("syscall", 10000)) if "compute" in args.phases else ()):
            for sample in range(min(args.samples, 7)):
                for engine in (("gvx", "wsl") if sample % 2 == 0 else ("wsl", "gvx")):
                    completed = run(command(engine, mode, f"-count={count}"), capture_output=True, timeout=120)
                    value = json.loads(completed.stdout)
                    if value["mode"] != mode or value["count"] != count or value["elapsed_ns"] <= 0:
                        raise RuntimeError("Compute output differs")
                    if mode == "cpu":
                        cpu_checksum = value["checksum"] if cpu_checksum is None else cpu_checksum
                        if value["checksum"] != cpu_checksum:
                            raise RuntimeError("CPU checksums differ")
                    results["compute"].append({"engine": engine, "sample": sample, **value})
                save()
            print(f"{mode} complete", flush=True)
        for count in (args.counts if "idle" in args.phases else []):
            for engine in ("wsl", "gvx"):
                guests = []
                vm_before = wsl_vm_cim()
                baseline = [memory_snapshot([]) for _ in range(3)]
                try:
                    for _ in range(count):
                        guests.append(start_guest(engine, "idle"))
                    roots = [guest.process.pid for guest in guests]
                    samples = [memory_snapshot(roots)]
                    deadline = time.perf_counter() + (args.idle_seconds if count == 1 else min(args.idle_seconds, 10))
                    while time.perf_counter() < deadline:
                        time.sleep(min(1, max(0, deadline - time.perf_counter())))
                        samples.append(memory_snapshot(roots))
                    results["idle"].append({"engine": engine, "instances": count, "baseline": baseline, "samples": samples,
                                             "wsl_vm_before_cim": vm_before, "wsl_vm_after_cim": wsl_vm_cim()})
                    save()
                finally:
                    close_guests(guests)
                print(f"{engine} idle instances={count} complete", flush=True)
        for sample in range(min(args.samples, 3) if "http" in args.phases else 0):
            for engine in (("gvx", "wsl") if sample % 2 == 0 else ("wsl", "gvx")):
                port = free_port()
                guest = start_guest(engine, "http", port)
                try:
                    with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=5)) as connection:
                        for _ in range(20):
                            http_request(connection)
                    start = time.perf_counter()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                        batches = list(pool.map(lambda _: http_worker(port, args.http_requests // 4), range(4)))
                    elapsed = time.perf_counter() - start
                    latencies = [value for values, _ in batches for value in values]
                    errors = [error for _, failures in batches for error in failures]
                    results["http"].append({"engine": engine, "sample": sample, "concurrency": 4,
                                             "elapsed_seconds": elapsed, "latencies_ms": latencies, "errors": errors})
                    save()
                finally:
                    guest.close()
            print(f"HTTP pair {sample + 1} complete", flush=True)
    except BaseException as error:
        results["failures"].append({"type": type(error).__name__, "message": str(error)})
        raise
    finally:
        save()
        run(wsl + ["rm", "-f", linux_binary])
        run(wsl + ["rmdir", linux_dir])
    (output / "summary.json").write_text(json.dumps(summarize(results), indent=2) + "\n", encoding="utf-8")
    for engine in ("gvx", "wsl"):
        values = [row["elapsed_ms"] for row in results["startup"] if row["engine"] == engine]
        if values:
            print(engine, "startup_ms", distribution(values), flush=True)
    print(output / "results.json", flush=True)


if __name__ == "__main__":
    main()
