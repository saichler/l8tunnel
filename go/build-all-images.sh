#!/usr/bin/env bash
# Builds and pushes every l8tunnel image, in deployment phase order.
# Usage: go/build-all-images.sh [amd64|arm64]   (blank builds both)
ARCH="$1"
case "$ARCH" in
    ""|amd64|arm64) ;;
    *) echo "Usage: $0 [amd64|arm64]"; exit 1 ;;
esac

# "<Display name>:<directory under go/tun/>"
IMAGES=(
    "Vnet:vnet"
    "Log Vnet:log-vnet"
    "Log Agent:log-agent"
    "Backend:main"
    "Registry:registry"
    "Relay:relay"
    "Edge:edge"
    "Web UI:ui"
)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUCCEEDED=()
FAILED=()

echo "*** Architecture: ${ARCH:-amd64 + arm64} ***"
for entry in "${IMAGES[@]}"; do
    NAME="${entry%%:*}"
    DIR="${entry##*:}"
    echo ""
    echo "*** Building ${NAME} ***"
    if "$SCRIPT_DIR/tun/$DIR/build.sh" "$ARCH"; then
        SUCCEEDED+=("$NAME")
    else
        echo "FAILED to build ${NAME}"
        FAILED+=("$NAME")
    fi
done

echo ""
echo "======================================================"
echo " Build summary (arch: ${ARCH:-amd64 + arm64})"
echo "======================================================"
for name in "${SUCCEEDED[@]}"; do echo "   OK      $name"; done
for name in "${FAILED[@]}"; do echo "   FAILED  $name"; done
[ ${#FAILED[@]} -eq 0 ]
