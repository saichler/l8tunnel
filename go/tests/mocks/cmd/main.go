// Command mocks uploads the l8tunnel mock data.
package main

import (
	"flag"

	"github.com/saichler/l8tunnel/go/tests/mocks"
)

func main() {
	address := flag.String("address", "https://localhost:5443", "l8tunnel web server address")
	user := flag.String("user", "admin", "user name")
	password := flag.String("password", "admin", "password")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	flag.Parse()
	mocks.RunMockGenerator(*address, *user, *password, *insecure)
}
