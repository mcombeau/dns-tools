package dns

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"
)

// ResolveQuery resolves a DNS query by querying servers, starting with the root rootServers
// until an authoritative answer is found.
//
// Parameters:
// - rootServers: the list of root servers to start querying
// - dnsRequest: the request to find an answer for
//
// Returns:
// - response: the DNS message containing the authoritative answer
// - err: an error if no response was found
func ResolveQuery(dnsRequest []byte) (response []byte, err error) {
	log.Printf("Resolving DNS query (len: %d): %v", len(dnsRequest), dnsRequest)

	rootServer := GetNextRootServer()

	response, err = queryServers([]Server{rootServer}, dnsRequest)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func queryServers(serverList []Server, dnsRequest []byte) (response []byte, err error) {
	dnsParsedRequest, err := DecodeMessage(dnsRequest)
	if err != nil {
		log.Printf("failed to parse client request: %v", err)
		return nil, err
	}
	domainQuery := dnsParsedRequest.Questions[0].Name

	for _, server := range serverList {

		serverAddr, err := server.getValidIPAddress()
		if err != nil {
			log.Printf("--> Moving on: server has no valid IP address: %v", err)
			continue
		}

		log.Printf("--> Querying server %s (IP: %v) for %s", server.Fqdn, serverAddr, domainQuery)

		response, err := sendDNSQuery(serverAddr, dnsRequest)
		if err != nil {
			log.Printf("failed to query server %s: %v", server, err)
			continue
		}

		dnsParsedResponse, err := DecodeMessage(response)
		if err != nil {
			log.Printf("failed to parse response from server %s: %v", server, err)
			return nil, err
		}

		if dnsParsedResponse.Header.AnswerRRCount > 0 {
			log.Printf("--> Got authoritative answer from server %s for %s", server, domainQuery)
			fmt.Println("-------------------")
			PrintMessage(dnsParsedResponse)
			fmt.Println("-------------------")

			return response, nil
		}

		if dnsParsedResponse.Header.NameserverRRCount > 0 || dnsParsedResponse.Header.AdditionalRRCount > 0 {
			authorityServers := extractAuthorityServerIPs(dnsParsedResponse)
			if len(authorityServers) > 0 {
				return queryServers(authorityServers, dnsRequest)
			}
		}
	}
	return nil, fmt.Errorf("failed to resolve DNS query")
}

func extractAuthorityServerIPs(dnsMessage Message) (serverList []Server) {
	if dnsMessage.Header.AdditionalRRCount > 0 {
		return extractAuthorityServerIPsFromAdditionals(dnsMessage)
	}

	// TODO: At this point we have NameServer entries but no IPs,
	// so resolve server names into IPs
	//
	// for _, nameServerRecord := range dnsMessage.NameServers {
	// 	if nameServerRecord.RType == NS {
	// 		nsRecord := nameServerRecord.RData.String()
	// 		nameServerQuery, err := CreateQuery(nsRecord, A)
	// 		if err != nil {
	// 			continue
	// 		}
	// 		response, err := queryServers(RootServers[:], nameServerQuery)
	// 		if err != nil {
	// 			continue
	// 		}
	// 		parsedResponse, err := DecodeMessage(response)
	// 		if err != nil {
	// 			continue
	// 		}
	// 		serverList = append(serverList, extractAuthorityServerIPs(parsedResponse)...)
	// 	}
	// }
	return serverList
}

func extractAuthorityServerIPsFromAdditionals(dnsMessage Message) (serverList []Server) {
	for _, additional := range dnsMessage.Additionals {
		serverName := additional.Name
		aRecord := additional.RData.String()

		switch additional.RType {
		case A:
			serverAddr, err := netip.ParseAddr(aRecord)
			if err == nil {
				serverList = append(serverList, Server{Fqdn: MakeFQDN(serverName), IPv4: serverAddr})
			}
		case AAAA:
			serverAddr, err := netip.ParseAddr(aRecord)
			if err == nil {
				serverList = append(serverList, Server{Fqdn: MakeFQDN(serverName), IPv6: serverAddr})
			}
		}
	}
	return serverList
}

func sendDNSQuery(server netip.Addr, dnsRequest []byte) (response []byte, err error) {
	serverAddrPort := netip.AddrPortFrom(server, defaultDNSPort)

	serverAddr := net.UDPAddrFromAddrPort(serverAddrPort)

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial server: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(dnsRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to send DNS request to server: %w", err)
	}

	receivedResponse := [4096]byte{}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(receivedResponse[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read response from root server: %w", err)
	}

	return receivedResponse[:n], nil
}
