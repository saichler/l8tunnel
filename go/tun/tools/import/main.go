// Command import loads a standalone relay's export into the cluster:
//
//	import -address https://<web>:5443 -user admin [-insecure] export/export.json
//
// Load the export's agent CA first: k8s/secrets.sh <context> export/
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/saichler/l8tunnel/go/tun/importer"
)

func main() {
	address := flag.String("address", "https://localhost:5443", "l8tunnel web server address")
	user := flag.String("user", "admin", "user name")
	password := flag.String("password", "", "password (default: the L8TUNNEL_PASSWORD environment variable)")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: import [flags] <export.json>")
		flag.PrintDefaults()
		os.Exit(2)
	}
	if *password == "" {
		*password = os.Getenv("L8TUNNEL_PASSWORD")
	}
	resp, err := importer.Import(*address, *user, *password, flag.Arg(0), *insecure)
	if err != nil {
		fmt.Fprintln(os.Stderr, "import:", err)
		os.Exit(1)
	}
	fmt.Printf("imported %d tokens, %d reservations, %d gateway keys\n",
		resp.ImportedTokens, resp.ImportedReservations, resp.ImportedGatewayKeys)
}
