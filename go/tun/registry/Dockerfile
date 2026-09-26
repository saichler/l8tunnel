FROM saichler/builder:latest AS build

# Populated by buildx from --platform (blank = the host's).
ARG TARGETOS=linux
ARG TARGETARCH

COPY main.go /home/src/github.com/saichler/build/main.go
RUN go mod init
RUN GOPROXY=direct GOPRIVATE=github.com go mod tidy
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o l8tunnelregistry

FROM saichler/l8tunnel-security:latest AS final
COPY --from=build /home/src/github.com/saichler/build/l8tunnelregistry /home/run/l8tunnelregistry
RUN mkdir -p /data && chmod 777 /data
ENTRYPOINT ["/home/run/l8tunnelregistry"]
