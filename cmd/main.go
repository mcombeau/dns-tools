package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/mcombeau/dns-tools/dns"
)

const maxUint16 = ^uint16(0) // ^ negation: sets all bits to 1: 65535

func main() {
	dnsServer := "8.8.8.8:53" // Google's public DNS server
	domain, questionType := parseArgs()

	// Seed the RNG for DNS header ID
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	message := &dns.Message{
		Header: &dns.Header{
			Id:            uint16(rng.Intn(int(maxUint16) + 1)),
			Flags:         dns.Flags{RecursionDesired: true},
			QuestionCount: 1,
		},
		Questions: []dns.Question{
			{
				Name:   domain,
				QType:  questionType,
				QClass: dns.IN,
			},
		},
	}

	data, err := dns.EncodeMessage(message)
	if err != nil {
		log.Fatalf("Failed to encode DNS message: %v\n", err)
	}

	startTime := time.Now()

	tcpQuery := false
	response, err := sendDNSQuery("udp", dnsServer, data)
	if err != nil {
		log.Fatalf("Failed to send DNS query over UDP: %v\n", err)
	}

	decodedMessage, err := dns.DecodeMessage(response)
	if err != nil {
		log.Fatalf("Failed to decode DNS response: %v\n", err)
	}

	if decodedMessage.Header.Flags.Truncated {
		// If UDP response is truncated (i.e. larger than 512 bytes)
		// fall back to TCP

		tcpQuery = true
		response, err := sendDNSQuery("tcp", dnsServer, data)
		if err != nil {
			log.Fatalf("Failed to send DNS query over TCP: %v\n", err)
		}

		decodedMessage, err = dns.DecodeMessage(response)
		if err != nil {
			log.Fatalf("Failed to decode DNS response: %v\n", err)
		}
	}

	queryTime := time.Since(startTime)

	dns.PrintBasicQueryInfo(domain, questionType)
	dns.PrintMessage(decodedMessage)
	dns.PrintQueryInfo(dnsServer, queryTime, tcpQuery, len(response))
}

func sendDNSQuery(transmissionProtocol string, server string, data []byte) ([]byte, error) {
	conn, err := net.Dial(transmissionProtocol, server)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DNS server: %v", err)
	}
	defer conn.Close()

	if transmissionProtocol == "tcp" {
		// Messages sent over TCP connections use server port 53 (decimal).
		// The message is prefixed with a two byte length field which gives
		// the message length, excluding the two byte length field.

		length := uint16(len(data))    // ex. 00000001	00101100
		highByte := byte(length >> 8)  // ex.			00000001
		lowByte := byte(length & 0xFF) // ex. 			00101100

		data = append([]byte{highByte, lowByte}, data...)
	}

	_, err = conn.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to send DNS query: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS response: %v", err)
	}

	if transmissionProtocol == "tcp" {
		// Skip the first two length prefix bytes
		response = response[2:n]
	} else {
		response = response[:n]
	}

	return response, nil
}

func parseArgs() (string, uint16) {
	reverseDNSQuery := flag.Bool("x", false, "Perform a reverse DNS query")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: go run main.go [-x] <domain_or_ip> [question_type]\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -h\tDisplay this help message\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 || flag.NArg() > 2 {
		flag.Usage()
		os.Exit(0)
	}

	var domain string
	var questionType uint16
	var err error

	if *reverseDNSQuery {
		ip := flag.Arg(0)
		questionType = dns.PTR
		domain, err = dns.GetReverseDNSDomain(ip)
		if err != nil {
			log.Fatalf("Get Reverse DNS Domain from IP address: %v\n", err)
		}
	} else {
		domain = flag.Arg(0)
		questionType = dns.A // Default to A
		if flag.NArg() == 2 {
			questionType = dns.GetRecordTypeFromTypeString(flag.Arg(1))
		}
	}

	return domain, questionType
}
