FROM saichler/builder:latest AS build

ENV CGO_ENABLED 1
COPY main.go /home/src/github.com/saichler/build/main.go
RUN go mod init
RUN GOPROXY=direct GOPRIVATE=github.com go mod tidy
RUN go mod vendor

WORKDIR /
RUN /patch.sh

WORKDIR /home/src/github.com/saichler/build
RUN go build -o l8tunnelvnet

FROM saichler/l8tunnel-security:latest AS final
COPY --from=build /home/src/github.com/saichler/build/l8tunnelvnet /home/run/l8tunnelvnet
RUN mkdir -p /data
RUN chmod 777 /data
ENTRYPOINT ["/home/run/l8tunnelvnet"]
