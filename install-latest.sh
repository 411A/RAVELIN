#!/bin/sh
set -eu

repo="411A/RAVELIN"
api_url="https://api.github.com/repos/${repo}/releases/latest"

case "$(uname -m)" in
  x86_64 | amd64)
    asset_pattern='linux-x86_64\.tar\.gz'
    ;;
  *)
    echo "RAVELIN installer error: unsupported architecture $(uname -m)" >&2
    exit 1
    ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "RAVELIN installer error: run as root, for example: curl -fsSL ... | sudo sh" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "RAVELIN installer error: curl is required" >&2
  exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
  echo "RAVELIN installer error: tar is required" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

echo "[RAVELIN] Resolving latest Linux release..."
asset_url="$(
  curl -fsSL "$api_url" \
    | sed -n 's/.*"browser_download_url":[[:space:]]*"\([^"]*\)".*/\1/p' \
    | grep -E "$asset_pattern" \
    | head -n 1 \
    || true
)"

if [ -z "$asset_url" ]; then
  echo "RAVELIN installer error: no matching release asset found for $(uname -m)" >&2
  exit 1
fi

archive="$tmp_dir/ravelin.tar.gz"
extract_dir="$tmp_dir/extract"
mkdir -p "$extract_dir"

echo "[RAVELIN] Downloading $asset_url"
curl -fL "$asset_url" -o "$archive"
tar -xzf "$archive" -C "$extract_dir"

package_dir="$(find "$extract_dir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
if [ -z "$package_dir" ] || [ ! -x "$package_dir/install.sh" ]; then
  echo "RAVELIN installer error: release package is missing install.sh" >&2
  exit 1
fi

exec "$package_dir/install.sh"
