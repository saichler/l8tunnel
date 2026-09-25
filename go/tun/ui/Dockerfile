FROM saichler/builder:latest AS build

COPY ./main/main.go /home/src/github.com/saichler/build/

RUN go mod init
RUN GOPROXY=direct GOPRIVATE=github.com go mod tidy
RUN go build -o l8tunnelweb

FROM saichler/l8tunnel-security:latest AS final
COPY --from=build /home/src/github.com/saichler/build/l8tunnelweb /home/run/l8tunnelweb
COPY ./web /home/run/web
WORKDIR /home/run

ENTRYPOINT ["/home/run/l8tunnelweb"]
