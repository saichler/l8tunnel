#!/usr/bin/env bash
# Generates the Go bindings for the l8tunnel protocol using the protoc image.
# This is the only supported way to produce go/types/l8tunnel/*.pb.go.
set -e
cd "$(dirname "$0")"

docker run --user "$(id -u):$(id -g)" -e PROTO=l8tunnel.proto --mount type=bind,source="$PWD",target=/home/proto/ -i saichler/protoc:latest

# Move the generated Go bindings into the module and clean up
mkdir -p ../go/types/l8tunnel
mv ./types/l8tunnel/*.pb.go ../go/types/l8tunnel/.
rm -rf ./types ./*.rs
