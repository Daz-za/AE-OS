#!/bin/sh
# Compile the example Rego policies to WebAssembly for the Python package, and copy each
# source beside its module so the browser page can show it.
#   policy/build.sh          write python/src/aeos/policies/<name>.wasm and <name>.rego
#   policy/build.sh --check  fail if the committed files differ from a fresh build
# Needs OPA on the PATH (CI pins the version; see .github/workflows/ci.yml).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
dest="$here/../python/src/aeos/policies"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
status=0
for pair in payments:aeos/payments/decision close:aeos/close/decision; do
  name=${pair%%:*}
  entry=${pair#*:}
  # Build from inside policy/ so the module records the relative file name, not this
  # machine's path, and every checkout builds the same bytes.
  (cd "$here" && opa build -t wasm -e "$entry" "$name.rego" -o "$tmp/$name.tar.gz")
  mkdir -p "$tmp/$name"
  tar -xzf "$tmp/$name.tar.gz" -C "$tmp/$name" /policy.wasm 2>/dev/null || tar -xzf "$tmp/$name.tar.gz" -C "$tmp/$name"
  if [ "${1:-}" = "--check" ]; then
    if cmp -s "$tmp/$name/policy.wasm" "$dest/$name.wasm" && cmp -s "$here/$name.rego" "$dest/$name.rego"; then
      echo "$name.wasm matches policy/$name.rego"
    else
      echo "$name.wasm or $name.rego is out of date; run policy/build.sh and commit the result" >&2
      status=1
    fi
  else
    cp "$tmp/$name/policy.wasm" "$dest/$name.wasm"
    cp "$here/$name.rego" "$dest/$name.rego"
    echo "wrote $dest/$name.wasm"
  fi
done
exit $status
