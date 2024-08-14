package main

import (
	"log"

	"github.com/mcombeau/dns-tools/internal/dnsResolver"
	"github.com/mcombeau/dns-tools/internal/dnsServer"
)

// TODO: Gameplan:
// - Setup server as listener on port 5553 (arbitrary choice of port)
// - Query public DNS like 8.8.8.8 or 1.1.1.1 for root servers
// - When a query arrives:
// 		- query root servers, parse response,
// 		- query next server, parse response,
// 		- etc until authoritative response.
// Later:
// 		- add caching
//		- handle multiple concurrent client requests

func main() {
	dnsResolver.FetchRootServers()

	err := dnsServer.StartUDPServer()
	if err != nil {
		log.Fatalf("failed to start UDP server: %v", err)
	}
}
