#!/usr/bin/env bash
#
# install.sh — deploy under ~/bin (co-located, collision-free layout).
#
#   $BIN_DIR/hoffa/       the importable package
#   $BIN_DIR/kb/          flat-file KB (sibling of the package)
#   $BIN_DIR/jimmy        thin wrapper, chmod 0700  (the PATH command)
#   $CONFIG_PATH          ~/.hoffa.toml, chmod 0600, not overwritten
#
# Package dir (hoffa) and wrapper (jimmy) have distinct names, so both live
# under $BIN_DIR without collision. The wrapper inserts its own dir onto
# sys.path, so `import hoffa` resolves with no PYTHONPATH. KB loader defaults
# to <wrapper_dir>/../kb == $BIN_DIR/kb.
#
# Idempotent: package and kb refreshed on re-run; existing config untouched.

set -euo pipefail

BIN_DIR="${HOFFA_BIN_DIR:-$HOME/bin}"
CONFIG_PATH="${HOFFA_CONFIG_PATH:-$HOME/.hoffa.toml}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for req in hoffa kb jimmy; do
    if [[ ! -e "$SRC_DIR/$req" ]]; then
        echo "[!] Missing source component: $SRC_DIR/$req" >&2
        exit 1
    fi
done

mkdir -p "$BIN_DIR"

# package
rm -rf "${BIN_DIR:?}/hoffa"
cp -r "$SRC_DIR/hoffa" "$BIN_DIR/hoffa"
find "$BIN_DIR/hoffa" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
echo "[+] Package installed: $BIN_DIR/hoffa"

# kb (merge, don't wipe — preserve user-added .kb files)
mkdir -p "$BIN_DIR/kb"
cp -r "$SRC_DIR/kb/." "$BIN_DIR/kb/"
echo "[+] KB installed: $BIN_DIR/kb"

# wrapper
install -m 0700 "$SRC_DIR/jimmy" "$BIN_DIR/jimmy"
echo "[+] Wrapper installed: $BIN_DIR/jimmy (0700)"

# config
if [[ -e "$CONFIG_PATH" ]]; then
    chmod 0600 "$CONFIG_PATH"
    echo "[*] Config exists, left untouched (perms set 0600): $CONFIG_PATH"
elif [[ -f "$SRC_DIR/hoffa.toml" ]]; then
    cp "$SRC_DIR/hoffa.toml" "$CONFIG_PATH"
    chmod 0600 "$CONFIG_PATH"
    echo "[+] Config template installed: $CONFIG_PATH (0600)"
else
    echo "[*] No config template found; runs on defaults."
fi

case ":$PATH:" in
    *":$BIN_DIR:"*) : ;;
    *) echo "[!] $BIN_DIR is not in PATH. Add to your shell rc:"
       echo "      export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

echo "[+] Done. Invoke with: jimmy"
