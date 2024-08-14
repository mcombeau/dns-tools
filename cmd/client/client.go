package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/mcombeau/dns-tools/pkg/dns"
)

func main() {
	dnsResolver, domainOrIP, questionType, reverseQuery, err := parseArgs()
	if err != nil {
		log.Fatalf("Failed to parse args: %v\n", err)
	}

	domain, err := parseQueryDomain(domainOrIP, reverseQuery, questionType)
	if err != nil {
		log.Fatalf("Bad DNS query: %v\n", err)
	}

	query, err := dns.CreateQuery(domain, questionType)
	if err != nil {
		log.Fatalf("Failed to create DNS query: %v\n", err)
	}

	startTime := time.Now()

	tcpQuery := false
	response, err := sendDNSQuery("udp", dnsResolver, query)
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
		response, err := sendDNSQuery("tcp", dnsResolver, query)
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
	dns.PrintQueryInfo(dnsResolver, queryTime, tcpQuery, len(response))
}

func parseQueryDomain(domainOrIP string, reverseQuery bool, questionType uint16) (fqdn string, err error) {
	var domain string

	_, err = netip.ParseAddr(domainOrIP)

	if err != nil { // Not an IP address
		if reverseQuery {
			return "", fmt.Errorf("Reverse DNS query must be an IP address: %v", err)
		}

		domain = dns.MakeFQDN(domainOrIP)

	} else { // IP address

		if !reverseQuery {
			return "", fmt.Errorf("Query must be a reverse query (-x) for IP address")
		} else if questionType != dns.PTR {
			return "", fmt.Errorf("Question type must be PTR (%d) for reverse query", dns.PTR)
		}

		domain, err = dns.GetReverseDomainFromIP(domainOrIP)
		if err != nil {
			return "", fmt.Errorf("Failed to get reverse query domain: %v)", err)
		}
	}
	return domain, nil
}

func sendDNSQuery(transmissionProtocol string, server string, data []byte) (response []byte, err error) {
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

	receivedResponse := [dns.MaxDNSMessageSize]byte{}
	n, err := conn.Read(receivedResponse[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS response: %v", err)
	}

	if transmissionProtocol == "tcp" {
		// Skip the first two length prefix bytes
		response = receivedResponse[2:n]
	} else {
		response = receivedResponse[:n]
	}

	return response, nil
}

func parseArgs() (dnsResolver string, domainOrIP string, questionType uint16, reverseQuery bool, err error) {
	reverseDNSQuery := flag.Bool("x", false, "Perform a reverse DNS query")

	var server string
	var port string
	flag.StringVar(&server, "s", "", "Specify the DNS resolver server address")
	flag.StringVar(&port, "p", "53", "Specify the DNS resolver server port")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: go run main.go [-s server] [-p port] [-x] <domain_or_ip> [question_type]\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -h\tDisplay this help message\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() < 1 || flag.NArg() > 2 {
		flag.Usage()
		os.Exit(0)
	}

	domainOrIP = flag.Arg(0)

	questionType = dns.A // Default to A
	if flag.NArg() == 2 {
		questionType = dns.GetRecordTypeFromTypeString(flag.Arg(1))
		if questionType == 0 {
			return "", "", 0, false, fmt.Errorf("invalid query: unknown question type: %s", flag.Arg(1))
		}
	}

	reverseQuery = *reverseDNSQuery

	dnsResolver, err = getDNSResolver(server, port)
	if err != nil {
		return "", "", 0, false, fmt.Errorf("get DNS resolver: %w", err)
	}

	return dnsResolver, domainOrIP, questionType, reverseQuery, nil
}

func getDNSResolver(server string, port string) (dnsResolver string, err error) {
	if server == "" {
		server, err = getDefaultDNSResolver()
		if err != nil {
			return "", fmt.Errorf("error getting default DNS resolver: %w", err)
		}
	}
	return fmt.Sprintf("%s:%s", server, port), nil
}

func getDefaultDNSResolver() (server string, err error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("cannot open /etc/resolv.conf: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				return fields[1], nil
			}
		}
	}

	if err = scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading /etc/resolv.conf: %w", err)
	}

	return "", fmt.Errorf("no nameserver found in /etc/resolv.conf")
}
