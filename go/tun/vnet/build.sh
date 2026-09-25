#!/usr/bin/env bash
set -e
# $1: amd64, arm64, or blank to build both.
cd "$(dirname "$0")"
case "$1" in
    amd64) PLATFORM=linux/amd64 ;;
    arm64) PLATFORM=linux/arm64 ;;
    "") PLATFORM=linux/amd64,linux/arm64 ;;
    *) echo "Usage: $0 [amd64|arm64]"; exit 1 ;;
esac
docker buildx build --no-cache --platform=$PLATFORM -t saichler/l8tunnel-vnet:latest --push .
