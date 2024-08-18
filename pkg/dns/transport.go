package dns

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

// QueryResponse sends a DNS query to the specified server using either TCP or UDP.
func QueryResponse(transmissionProtocol string, serverAddrPort netip.AddrPort, dnsRequest []byte) (response []byte, err error) {
	var conn net.Conn

	// Dial the server using the specified protocol
	switch transmissionProtocol {
	case "tcp":
		conn, err = net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(serverAddrPort))
	case "udp":
		conn, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(serverAddrPort))
	default:
		return nil, fmt.Errorf("unsupported transmission protocol: %s", transmissionProtocol)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to DNS server: %v", err)
	}
	defer conn.Close()

	if transmissionProtocol == "tcp" {
		// Add length prefix for TCP
		length := uint16(len(dnsRequest))
		highByte := byte(length >> 8)
		lowByte := byte(length & 0xFF)
		dnsRequest = append([]byte{highByte, lowByte}, dnsRequest...)
	}

	// Send the DNS request
	_, err = conn.Write(dnsRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to send DNS request: %v", err)
	}

	// Set a read deadline
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Read the response
	receivedResponse := [4096]byte{}
	n, err := conn.Read(receivedResponse[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read DNS response: %v", err)
	}

	if transmissionProtocol == "tcp" {
		// Skip the first two length prefix bytes for TCP
		response = receivedResponse[2:n]
	} else {
		response = receivedResponse[:n]
	}

	return response, nil
}
