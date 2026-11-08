#!/usr/bin/env bash
# Runs one executable of the probe app on the device that adb selects.
#
# Usage: scripts/android/run-probe.sh EXE [ARG...]
#   EXE is libandroidprobe.so or librungv.so. An argument may contain
#   @FILES@, which the app replaces with its files directory.
# Example: scripts/android/run-probe.sh librungv.so run -platform=systrap -bin @FILES@/guests/guest-pie
set -euo pipefail

exe=${1:?usage: run-probe.sh EXE [ARG...]}
shift
# Join the arguments with NUL bytes. BSD and GNU head differ, so a loop
# writes the separators.
args64=$(
	sep=""
	for a in "$@"; do
		printf "$sep%s" "$a"
		sep='\0'
	done | base64 | tr -d '\n'
)
adb shell am instrument -w -e exe "$exe" -e args64 "'$args64'" dev.gfire.gvx.probe/.Run
