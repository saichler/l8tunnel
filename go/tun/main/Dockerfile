FROM saichler/builder:latest AS build

# Populated by buildx from --platform (blank = the host's).
ARG TARGETOS=linux
ARG TARGETARCH

COPY main.go /home/src/github.com/saichler/build/main.go
RUN go mod init
RUN GOPROXY=direct GOPRIVATE=github.com go mod tidy
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o l8tunnel

FROM saichler/l8tunnel-postgres:latest AS final

COPY --from=build /home/src/github.com/saichler/build/l8tunnel /home/run/l8tunnel
COPY start.sh /home/run/start.sh
RUN chmod +x /home/run/start.sh

ENTRYPOINT ["/home/run/start.sh"]
