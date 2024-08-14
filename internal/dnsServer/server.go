package dnsServer

import (
	"fmt"
	"log"
	"net"

	"github.com/mcombeau/dns-tools/internal/dnsResolver"
)

const DNSResolverIP = "0.0.0.0"
const DNSResolverPort = 5553

const MaxUDPMessageLength = 512

func StartUDPServer() (err error) {
	addr := net.UDPAddr{
		Port: DNSResolverPort,
		IP:   net.ParseIP(DNSResolverIP),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return fmt.Errorf("failed to set up UDP listener: %w", err)
	}
	defer conn.Close()

	log.Printf("DNS resolver server listening on port: %d", addr.Port)

	buffer := [MaxUDPMessageLength]byte{}
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer[:])
		if err != nil {
			log.Printf("error reading from UDP: %v", err)
			continue
		}

		// TODO: Make this concurrent to handle multiple simultanous requests
		handleDNSRequest(conn, clientAddr, buffer[:n])
	}
}

func handleDNSRequest(conn *net.UDPConn, clientAddr *net.UDPAddr, request []byte) {
	response, err := dnsResolver.ResolveDNSQuery(request)
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
