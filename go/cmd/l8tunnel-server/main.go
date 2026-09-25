// Command l8tunnel-server is the public relay.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
)

func main() {
	listen := flag.String("listen", ":443", "address agents connect to")
	certFile := flag.String("cert", "", "TLS certificate file (PEM)")
	keyFile := flag.String("key", "", "TLS private key file (PEM)")
	tokensFile := flag.String("tokens-file", "", "file with one \"<name> <token>\" per line")
	publicHost := flag.String("public-host", "", "public host name reported to agents")
	bindHost := flag.String("bind", "", "address public tunnel ports bind to (default: all)")
	tcpPorts := flag.String("tcp-ports", "22000-22999", "public port range for TCP/SSH tunnels")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(logger, *listen, *certFile, *keyFile, *tokensFile, *publicHost, *bindHost, *tcpPorts); err != nil {
		fmt.Fprintln(os.Stderr, "l8tunnel-server:", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, listen, certFile, keyFile, tokensFile, publicHost, bindHost, tcpPorts string) error {
	tlsCfg, err := transport.ServerTLSConfig(certFile, keyFile)
	if err != nil {
		return err
	}
	tokens, err := auth.LoadTokensFile(tokensFile)
	if err != nil {
		return err
	}
	portMin, portMax, err := relay.ParsePortRange(tcpPorts)
	if err != nil {
		return err
	}
	srv, err := relay.New(relay.Config{
		ControlAddr: listen,
		TLS:         tlsCfg,
		Tokens:      tokens,
		PublicHost:  publicHost,
		BindHost:    bindHost,
		TCPPortMin:  portMin,
		TCPPortMax:  portMax,
		Logger:      logger,
	})
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return err
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("shutting down", "signal", (<-sig).String())
	return srv.Close()
}
