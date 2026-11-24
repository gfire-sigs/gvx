#!/bin/bash
# gvx Chromium sandbox probe. Run it as a user other than root. It starts
# Chromium with its own sandbox on, waits until a renderer process applies its
# seccomp filter, and prints one "GVX-SB" line for each Chromium process: the
# process type, the seccomp mode, and the user and PID namespaces.
set -u
chrome=$(ls /ms-playwright/chromium-*/chrome-linux*/chrome | head -n 1)
"$chrome" --headless=new --disable-gpu --remote-debugging-port=9222 \
	file:///workspace/hello.html >/tmp/chrome.log 2>&1 &
browser=$!

# Poll for at most 60 s (600 x 0.1 s) for a renderer in seccomp mode 2.
ready=0
for _ in $(seq 1 600); do
	for status in /proc/[0-9]*/status; do
		dir=${status%/status}
		tr '\0' ' ' 2>/dev/null <"$dir/cmdline" | grep -q -- '--type=renderer' || continue
		grep -q '^Seccomp:[[:space:]]*2' "$status" 2>/dev/null && ready=1
	done
	[ "$ready" = 1 ] && break
	kill -0 "$browser" 2>/dev/null || break
	grep -q '^State:[[:space:]]*Z' "/proc/$browser/status" 2>/dev/null && break
	sleep 0.1
done
echo "GVX-SB ready=$ready"

for dir in /proc/[0-9]*; do
	cmd=$(tr '\0' ' ' 2>/dev/null <"$dir/cmdline") || continue
	case "$cmd" in "$chrome"*) ;; *) continue ;; esac
	type=$(printf '%s\n' "$cmd" | grep -o -- '--type=[a-z-]*' | head -n 1)
	type=${type#--type=}
	[ "${dir#/proc/}" = "$browser" ] && type=browser
	[ -n "$type" ] || continue
	seccomp=$(awk '/^Seccomp:/ {print $2}' "$dir/status")
	echo "GVX-SB type=$type seccomp=$seccomp userns=$(readlink "$dir/ns/user") pidns=$(readlink "$dir/ns/pid")"
done
kill "$browser" 2>/dev/null || true
wait "$browser" 2>/dev/null || true
if [ "$ready" != 1 ]; then
	cat /tmp/chrome.log >&2 2>/dev/null || true
	exit 1
fi
echo "GVX-SB done"
