package main

import (
	"fmt"
	"log"
	"net"
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
const ServerIP = "0.0.0.0"
const ServerPort = 5553

func main() {
	rootServers, err := loadRootServers(RootServerHintsFile)
	if err != nil {
		log.Fatalf("Failed to load root servers: %v", err)
	}

	if err := startUDPServer(rootServers); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func loadRootServers(filename string) (rootServers []dns.Server, err error) {
	log.Printf("Loading root servers from: %s\n", filename)

	file, err := os.Open(filename)
	if err != nil {
		log.Printf("Error opening %s: %v\n", filename, err)
		// TODO: if error with root server hints file, try bootstrapping via public DNS
	}
	defer file.Close()

	return dns.ParseRootServerHints(file)
}

func startUDPServer(rootServers []dns.Server) (err error) {
	addr := net.UDPAddr{
		Port: ServerPort,
		IP:   net.ParseIP(ServerIP),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return fmt.Errorf("failed to set up UDP listener: %w", err)
	}
	defer conn.Close()

	log.Printf("DNS resolver server listening on port: %d", addr.Port)

	buffer := [dns.MaxUDPMessageLength]byte{}
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer[:])
		if err != nil {
			log.Printf("error reading from UDP: %v", err)
			continue
		}

		go handleRequest(conn, clientAddr, buffer[:n], rootServers)
	}
}

func handleRequest(conn *net.UDPConn, clientAddr *net.UDPAddr, request []byte, rootServers []dns.Server) {
	response, err := dns.ResolveQuery(rootServers, request)
	if err != nil {
		log.Printf("failed to resolve DNS request from client %v: %v", clientAddr, err)
		return
	}

	_, err = conn.WriteToUDP(response, clientAddr)
	if err != nil {
		log.Printf("failed to send response to client %v: %v", clientAddr, err)
		return
	}
}
