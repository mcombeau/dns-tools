package dns

import (
	"fmt"
	"log"
	"net/netip"
)

const MaxRecursionDepth = 5

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

	// TODO: cache answers and check cache before querying servers

	// TODO: ping root server here to check if it's alive and if not get next root server again?
	rootServer := GetNextRootServer()

	response, err = queryServers([]Server{rootServer}, dnsRequest, 0)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func queryServers(serverList []Server, dnsRequest []byte, depth int) (response []byte, err error) {

	if depth >= MaxRecursionDepth {
		return nil, fmt.Errorf("recursion depth exceeded")
	}

	dnsParsedRequest, err := DecodeMessage(dnsRequest)
	if err != nil {
		log.Printf("failed to parse client request: %v", err)
		return nil, err
	}
	domainQuery := dnsParsedRequest.Questions[0].Name

	for _, server := range serverList {

		serverAddrPort, err := server.getValidIPAddress()
		if err != nil {
			log.Printf("--> Moving on: server has no valid IP address: %v", err)
			continue
		}

		log.Printf("--> Querying server %s (IP: %v) for %s", server.Fqdn, serverAddrPort, domainQuery)

		response, err := QueryResponse("udp", serverAddrPort, dnsRequest)
		if err != nil {
			log.Printf("failed to query server %s: %v", server, err)
			continue
		}

		dnsParsedResponse, err := DecodeMessage(response)
		if err != nil {
			log.Printf("Failed to parse response from server %s: %v", server, err)
			return nil, err
		}

		if dnsParsedResponse.ContainsAuthoritativeAnswer() {
			log.Printf("--> Got authoritative answer from server %s for %s", server, domainQuery)
			fmt.Println("-------------------")
			PrintMessage(dnsParsedResponse)
			fmt.Println("-------------------")

			return response, nil
		}

		if dnsParsedResponse.ContainsAdditionalSection() {
			log.Printf("--> Got no answer from server %s for %s, but got additional records", server, domainQuery)
			authorityServers := extractNameServerIPs(dnsParsedResponse.Additionals)
			if len(authorityServers) > 0 {
				return queryServers(authorityServers, dnsRequest, depth+1)
			} else {
				return nil, fmt.Errorf("could not parse additional section in response from server %s", server)
			}
		}

		if dnsParsedResponse.ContainsAuthoritySection() {
			log.Printf("--> Got no answer or additional records from server %s for %s, but got NS records", server, domainQuery)
			authorityServers := resolveNameServerRecords(dnsParsedResponse, server, depth+1)
			if len(authorityServers) > 0 {
				return queryServers(authorityServers, dnsRequest, depth+1)
			} else {
				return nil, fmt.Errorf("could not parse authority section in response from server %s", server)
			}
		}
	}
	return nil, fmt.Errorf("failed to resolve DNS query")
}

func resolveNameServerRecords(dnsMessage Message, originalServer Server, depth int) (serverList []Server) {
	for _, nameServerRecord := range dnsMessage.NameServers {
		if nameServerRecord.RType == NS {
			nsRecord := nameServerRecord.RData.String()

			// TODO: setup nameserver cache system to avoid overquerying servers

			fmt.Printf("\t\t--> nsRecord: %s\n", nsRecord)
			nameServerQuery, err := CreateQuery(nsRecord, A)
			if err != nil {
				continue
			}

			// Query the server the response came from instead of going back up to root
			fmt.Printf("\t\t--> querying original server %v for nsRecord: %s\n", originalServer, nsRecord)
			response, err := queryServers([]Server{originalServer}, nameServerQuery, depth)
			if err != nil {
				continue
			}
			parsedResponse, err := DecodeMessage(response)
			if err != nil {
				continue
			}
			fmt.Printf("\t\t--> got response from servers for nsRecord: %s: %s\n", nsRecord, parsedResponse.Answers[0].RData.String())

			serverList = append(serverList, extractNameServerIPs(parsedResponse.Answers)...)
		}
	}
	return serverList
}

func extractNameServerIPs(dnsResourceRecord []ResourceRecord) (serverList []Server) {
	for _, record := range dnsResourceRecord {
		serverName := record.Name
		ipString := record.RData.String()

		var nameServer Server

		switch record.RType {
		case A:
			serverAddr, err := netip.ParseAddr(ipString)
			if err == nil {
				nameServer = Server{Fqdn: MakeFQDN(serverName), IPv4: serverAddr}
			}
		case AAAA:
			serverAddr, err := netip.ParseAddr(ipString)
			if err == nil {
				nameServer = Server{Fqdn: MakeFQDN(serverName), IPv6: serverAddr}
			}
		}
		serverList = append(serverList, nameServer)
		log.Printf("\t--> got NS record: %v", nameServer)
	}
	return serverList
}
