FROM saichler/builder:latest AS build

# Populated by buildx from --platform (blank = the host's).
ARG TARGETOS=linux
ARG TARGETARCH

COPY main.go /home/src/github.com/saichler/build/main.go
RUN go mod init
RUN GOPROXY=direct GOPRIVATE=github.com go mod tidy
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o l8tunnelrelay

FROM saichler/l8tunnel-security:latest AS final
COPY --from=build /home/src/github.com/saichler/build/l8tunnelrelay /home/run/l8tunnelrelay
RUN mkdir -p /data && chmod 777 /data
ENTRYPOINT ["/home/run/l8tunnelrelay"]
