package main

import (
	// "log"

	// "github.com/mcombeau/dns-tools/internal/server"
	"log"
	"os"

	"github.com/mcombeau/dns-tools/pkg/dns"
)

// TODO: Gameplan:
// - Setup server as listener on port 5553 (arbitrary choice of port)
// - Bootstrap with root servers
// - When a query arrives:
// 		- query root servers, parse response,
// 		- query next server, parse response,
// 		- etc until authoritative response.
// Later:
// 		- add caching
//		- handle multiple concurrent client requests

const RootServerHintsFile = "config/named.root"

func main() {
	log.Printf("Opening: %s\n", RootServerHintsFile)

	file, err := os.Open(RootServerHintsFile)
	if err != nil {
		log.Printf("Error opening %s: %v\n", RootServerHintsFile, err)
		// TODO: if error with root server hints file, try bootstrapping via public DNS
	}
	defer file.Close()

	log.Printf("Parsing: %s\n", RootServerHintsFile)

	rootServers, err := dns.ParseRootServerHints(file)
	if err != nil {
		log.Printf("Error opening %s: %v\n", RootServerHintsFile, err)
	}

	for _, server := range rootServers {
		log.Printf("Root server: %-25s A: %-15v AAAA: %-45v\n", server.Fqdn, server.IPv4, server.IPv6)
	}
}
