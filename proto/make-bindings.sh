#!/usr/bin/env bash
# Generates the Go bindings using the protoc image. This is the only
# supported way to produce go/types/l8tunnel/*.pb.go (the agent/relay wire
# protocol) and go/types/tun/*.pb.go (the management model).
set -e
cd "$(dirname "$0")"

# Imports of tun.proto, for resolution only: their Go code comes from the
# vendored l8types module.
wget -q https://raw.githubusercontent.com/saichler/l8types/refs/heads/main/proto/api.proto
wget -q https://raw.githubusercontent.com/saichler/l8types/refs/heads/main/proto/l8notify.proto

for p in l8tunnel.proto tun.proto; do
    docker run --user "$(id -u):$(id -g)" -e PROTO="$p" --mount type=bind,source="$PWD",target=/home/proto/ -i saichler/protoc:latest
done
rm -f api.proto l8notify.proto

# Move the generated Go bindings into the module and clean up
for pkg in l8tunnel tun; do
    rm -rf ../go/types/$pkg
    mkdir -p ../go/types/$pkg
    mv ./types/$pkg/*.pb.go ../go/types/$pkg/.
done
rm -rf ./types ./*.rs

# Point the imports of l8types' packages at the vendored module
cd ../go/types
sed -i 's|"./types/l8api"|"github.com/saichler/l8types/go/types/l8api"|g; s|"./types/l8notify"|"github.com/saichler/l8types/go/types/l8notify"|g' tun/*.pb.go
gofmt -w tun
