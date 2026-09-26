FROM saichler/builder:latest AS build

COPY main.go /home/src/github.com/saichler/build/main.go
RUN go mod init
RUN GOPROXY=direct GOPRIVATE=github.com go mod tidy
RUN go build -o l8tunneledge

FROM saichler/l8tunnel-security:latest AS final
COPY --from=build /home/src/github.com/saichler/build/l8tunneledge /home/run/l8tunneledge
RUN mkdir -p /data && chmod 777 /data
ENTRYPOINT ["/home/run/l8tunneledge"]
