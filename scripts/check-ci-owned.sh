#!/usr/bin/env bash
# Verifies that OWNED in .github/workflows/ci.yml covers every package with a
# Go test file outside e2e and pkg/sentry/platform/systrap.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -z "${OWNED:-}" ]; then
	OWNED=$(awk '
		/^  OWNED: >-/ { in_owned = 1; next }
		in_owned && /^    / { sub(/^    /, ""); printf "%s ", $0; next }
		in_owned { exit }
	' .github/workflows/ci.yml)
fi

if [ -z "${OWNED// /}" ]; then
	echo "OWNED is empty" >&2
	exit 1
fi

# shellcheck disable=SC2086
covered=$(
	for target in linux/amd64 linux/arm64 darwin/arm64 windows/amd64 windows/arm64; do
		GOOS=${target%/*} GOARCH=${target#*/} go list -e -f '{{if or .GoFiles .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' $OWNED ./e2e ./pkg/sentry/platform/systrap/...
	done | awk 'NF' | sort -u
)

missing=()
while IFS= read -r dir; do
	pkg="z.gfire.dev/gvx/${dir#./}"
	if ! grep -Fxq "$pkg" <<<"$covered"; then
		missing+=("$pkg")
	fi
done < <(find . \( -path './.git' -o -path './tools/shiminterop' -o -name testdata \) -prune -o -name '*_test.go' -print | sed 's|/[^/]*$||' | sort -u)

if [ "${#missing[@]}" -gt 0 ]; then
	printf 'Packages with _test.go missing from OWNED in .github/workflows/ci.yml:\n' >&2
	printf '  %s\n' "${missing[@]}" >&2
	exit 1
fi
