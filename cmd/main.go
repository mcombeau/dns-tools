package main

import (
	"bufio"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mcombeau/dns-tools/dns"
)

func main() {
	dnsResolver, domain, questionType, err := parseArgs()
	if err != nil {
		log.Fatalf("Failed to parse args: %v\n", err)
	}

	message := dns.Message{
		Header: dns.Header{
			Id:            generateRandomID(),
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
	response, err := sendDNSQuery("udp", dnsResolver, data)
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
		response, err := sendDNSQuery("tcp", dnsResolver, data)
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

func parseArgs() (dnsResolver string, domain string, questionType uint16, err error) {
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

	dnsResolver, err = getDNSResolver(server, port)
	if err != nil {
		return "", "", 0, fmt.Errorf("get DNS resolver: %w", err)
	}

	if *reverseDNSQuery {
		ip := flag.Arg(0)
		questionType = dns.PTR
		domain, err = dns.GetReverseDNSDomain(ip)
		if err != nil {
			return "", "", 0, fmt.Errorf("get Reverse DNS Domain from IP address: %w", err)
		}
	} else {
		domain = flag.Arg(0)
		questionType = dns.A // Default to A
		if flag.NArg() == 2 {
			questionType = dns.GetRecordTypeFromTypeString(flag.Arg(1))
		}
	}

	return dnsResolver, domain, questionType, nil
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

func generateRandomID() uint16 {
	bytes := [2]byte{}

	_, err := io.ReadFull(rand.Reader, bytes[:])
	if err != nil {
		panic(err)
	}

	return uint16(bytes[0])<<8 | uint16(bytes[1])
}
