#!/bin/sh
# Compile the example Rego policy to WebAssembly for the Python package.
#   policy/build.sh          write python/src/aeos/policies/payments.wasm
#   policy/build.sh --check  fail if the committed module differs from a fresh build
# Needs OPA on the PATH (CI pins the version; see .github/workflows/ci.yml).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out="$here/../python/src/aeos/policies/payments.wasm"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
# Build from inside policy/ so the module records the relative file name, not this
# machine's path, and every checkout builds the same bytes.
(cd "$here" && opa build -t wasm -e aeos/payments/decision payments.rego -o "$tmp/bundle.tar.gz")
tar -xzf "$tmp/bundle.tar.gz" -C "$tmp" /policy.wasm 2>/dev/null || tar -xzf "$tmp/bundle.tar.gz" -C "$tmp"
if [ "${1:-}" = "--check" ]; then
  if cmp -s "$tmp/policy.wasm" "$out"; then
    echo "payments.wasm matches policy/payments.rego"
  else
    echo "payments.wasm is out of date; run policy/build.sh and commit the result" >&2
    exit 1
  fi
else
  cp "$tmp/policy.wasm" "$out"
  echo "wrote $out"
fi
