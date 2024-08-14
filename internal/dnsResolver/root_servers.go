package dnsResolver

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/mcombeau/dns-tools/pkg/dns"
)

const publicDNSServer = "1.1.1.1:53"
const numberOfRootServers = 13

var rootServers [numberOfRootServers]string

func FetchRootServers() {
	// TODO: Maybe run this periodically to update root servers?
	rootServerNames := getRootServerNames()

	var rootServerIPs [numberOfRootServers]string
	var count int

	for i, serverName := range rootServerNames {
		ip, err := resolveWithPublicDNS(serverName)
		if err != nil {
			log.Printf("failed to resolve IP for server %s: %v", serverName, err)
			continue
		}

		rootServerIPs[i] = ip
		count++
	}

	if count < 1 {
		log.Panic("could not resolve IPs for root servers")
	}

	rootServers = rootServerIPs
	log.Printf("fetched root servers: %v", rootServers)
}

func getRootServerNames() (rootServerNames [numberOfRootServers]string) {
	for i := 0; i < numberOfRootServers; i++ {
		rootServerNames[i] = fmt.Sprintf("%c.root-servers.net.", 'a'+i)
	}
	return rootServerNames
}

func resolveWithPublicDNS(serverName string) (ip string, err error) {
	conn, err := net.Dial("udp", publicDNSServer)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	query, err := dns.CreateQuery(serverName, dns.A)
	if err != nil {
		return "", err
	}

	_, err = conn.Write(query)
	if err != nil {
		return "", err
	}

	response := [dns.MaxDNSMessageSizeOverUDP]byte{}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(response[:])
	if err != nil {
		return "", err
	}

	decodedResponse, err := dns.DecodeMessage(response[:n])
	if err != nil {
		return "", err
	}

	ip = decodedResponse.Answers[0].RData.String()
	_, err = netip.ParseAddr(ip)
	if err != nil {
		return "", err
	}

	return ip, nil
}
