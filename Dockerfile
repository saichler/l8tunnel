# Multi-stage build for the relay and the agent.
#   docker build --target server -t l8tunnel-server .
#   docker build --target agent  -t l8tunnel-agent .
ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src/go
COPY go/go.mod go/go.sum ./
RUN go mod download
COPY go/ ./
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ ./cmd/...
# State and socket directories, owned by distroless's nonroot user (65532).
RUN mkdir -p /dirs/server/var/lib/l8tunnel /dirs/server/run/l8tunnel /dirs/agent/run/l8tunnel-agent

# The relay: mount /etc/l8tunnel (server.yaml, certificates) and a volume
# for /var/lib/l8tunnel (database, ACME state).
FROM gcr.io/distroless/static-debian12:nonroot AS server
COPY --from=build /out/l8tunnel-server /usr/local/bin/l8tunnel-server
COPY --from=build --chown=65532:65532 /dirs/server/ /
VOLUME ["/var/lib/l8tunnel"]
EXPOSE 443 80
ENTRYPOINT ["/usr/local/bin/l8tunnel-server"]
CMD ["--config", "/etc/l8tunnel/server.yaml"]

# The agent (with the l8tunnel client helper): mount /etc/l8tunnel/agent.yaml
# or pass command-line arguments.
FROM gcr.io/distroless/static-debian12:nonroot AS agent
COPY --from=build /out/l8tunnel-agent /usr/local/bin/l8tunnel-agent
COPY --from=build /out/l8tunnel /usr/local/bin/l8tunnel
COPY --from=build --chown=65532:65532 /dirs/agent/ /
ENTRYPOINT ["/usr/local/bin/l8tunnel-agent"]
CMD ["--config", "/etc/l8tunnel/agent.yaml"]
