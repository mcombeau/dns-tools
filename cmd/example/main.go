package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/mcombeau/go-dns-tools/decoder"
	"github.com/mcombeau/go-dns-tools/encoder"
	"github.com/mcombeau/go-dns-tools/printer"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <domain>")
		return
	}

	domain := os.Args[1]
	dnsServer := "1.1.1.1:53" // CloudFlare's public DNS resolver

	question := encoder.EncodeDNSQuestion(domain)

	conn, err := net.Dial("udp", dnsServer)
	if err != nil {
		log.Fatalf("Failed to connect to DNS server: %v\n", err)
	}
	defer conn.Close()

	_, err = conn.Write(question)
	if err != nil {
		log.Fatalf("Failed to send DNS question: %v\n", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		log.Fatalf("Failed to read DNS response: %v\n", err)
	}

	fmt.Println("Received DNS response:")

	decodedMessage, err := decoder.DecodeDNSMessage(response[:n])
	if err != nil {
		log.Fatalf("Failed to decode DNS response: %v\n", err)
	}

	printer.PrintDNSMessage(decodedMessage)
}
