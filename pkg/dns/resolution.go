package dns

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
)

type Resolver struct {
	MaxRecursionDepth int
	RootServers       []Server

	// Query function reference for testing mock injection
	QueryFunc func(string, netip.AddrPort, []byte) ([]byte, error)
}

func NewResolver() (resolver *Resolver) {
	return &Resolver{MaxRecursionDepth: 10, QueryFunc: QueryResponse}
}

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
func (resolver *Resolver) ResolveQuery(dnsRequest []byte) (response []byte, err error) {
	log.Printf("Resolving DNS query (len: %d): %v", len(dnsRequest), dnsRequest)

	dnsParsedRequest, err := DecodeMessage(dnsRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client request: %w", err)
	}

	queryDomain := dnsParsedRequest.Questions[0].Name

	// TODO: cache answers and check cache before querying servers

	// TODO: ping root server here to check if it's alive and if not get next root server again?
	rootServer := resolver.GetNextRootServer()

	response, err = resolver.queryServers([]Server{rootServer}, dnsRequest, queryDomain, 0)
	if err != nil {
		if errors.Is(err, ErrServFailToResolveQuery) {
			dnsParsedRequest.Header.Flags.ResponseCode = SERVFAIL
			return EncodeMessage(dnsParsedRequest)
		}
		log.Printf("failed to resolve query: %v", err)
		return nil, err
	}

	return response, nil
}

func (resolver *Resolver) queryServers(serverList []Server, dnsRequest []byte, queryDomain string, depth int) (response []byte, err error) {

	if depth >= resolver.MaxRecursionDepth {
		return nil, fmt.Errorf("recursion depth exceeded")
	}

	for _, server := range serverList {

		serverAddrPort, err := server.getValidIPAddress()
		if err != nil {
			log.Printf("--> Moving on: server has no valid IP address: %v", err)
			continue
		}

		log.Printf("--> Querying server %s (IP: %v) for %s", server.Fqdn, serverAddrPort, queryDomain)

		response, err := resolver.QueryFunc("udp", serverAddrPort, dnsRequest)
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
			log.Printf("--> Got authoritative answer from server %s for %s", server, queryDomain)
			fmt.Println("-------------------")
			PrintMessage(dnsParsedResponse)
			fmt.Println("-------------------")

			return response, nil
		}

		if dnsParsedResponse.ContainsAdditionalSection() {
			log.Printf("--> Got no answer from server %s for %s, but got additional records", server, queryDomain)
			authorityServers := extractNameServerIPs(dnsParsedResponse.Additionals)
			if len(authorityServers) > 0 {
				return resolver.queryServers(authorityServers, dnsRequest, queryDomain, depth+1)
			} else {
				fmt.Println("------------------- ADDITIONAL SECTION IS EMPTY?")
				PrintMessage(dnsParsedResponse)
				fmt.Println("-------------------")

				return nil, fmt.Errorf("%w: could not parse additional section in response from server %s", ErrServFailToResolveQuery, server)
			}
		}

		if dnsParsedResponse.ContainsAuthoritySection() {
			log.Printf("--> Got no answer or additional records from server %s for %s, but got NS records", server, queryDomain)
			authorityServers := resolver.resolveNameServerRecords(dnsParsedResponse, server, depth+1)
			if len(authorityServers) > 0 {
				return resolver.queryServers(authorityServers, dnsRequest, queryDomain, depth+1)
			} else {
				fmt.Println("------------------- AUTHORITY SECTION IS EMPTY?")
				PrintMessage(dnsParsedResponse)
				fmt.Println("-------------------")
				return nil, fmt.Errorf("%w: could not parse authority section in response from server %s", ErrServFailToResolveQuery, server)
			}
		}

		if dnsParsedResponse.Header.Flags.ResponseCode == REFUSED {
			return nil, ErrServFailToResolveQueryRefused
		}
	}

	return nil, fmt.Errorf("%w: break in the chain", ErrServFailToResolveQuery)
}

func (resolver *Resolver) resolveNameServerRecords(dnsMessage Message, originalServer Server, depth int) (serverList []Server) {
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
			response, err := resolver.queryServers([]Server{originalServer}, nameServerQuery, nsRecord, depth)
			if err != nil {
				log.Printf("Failed to query original server %v for %s: %v", originalServer, nsRecord, err)

				// If original server refuses the request, query root server
				if err == ErrServFailToResolveQueryRefused {
					rootServer := resolver.GetNextRootServer()

					response, err = resolver.queryServers([]Server{rootServer}, nameServerQuery, nsRecord, depth)
					if err != nil {
						log.Printf("Failed to query original server %v for %s: %v", originalServer, nsRecord, err)
						continue
					}
				}
			}

			parsedResponse, err := DecodeMessage(response)
			if err != nil {
				log.Printf("Failed to decode message from server %v for %s: %v", originalServer, nsRecord, err)
				continue
			}

			fmt.Printf("\t\t--> got response from servers for nsRecord: %s: %s\n", nsRecord, parsedResponse.Answers[0].RData.String())

			serverList = append(serverList, extractNameServerIPs(parsedResponse.Answers)...)
		}
	}
	return serverList
}

func extractNameServerIPs(dnsResourceRecord []ResourceRecord) (serverList []Server) {
	serverMap := make(map[string]int)

	for _, record := range dnsResourceRecord {
		serverName := record.Name
		ipString := record.RData.String()

		index, exists := serverMap[serverName]
		if !exists {
			serverList = append(serverList, Server{Fqdn: serverName})
			index = len(serverList) - 1
			serverMap[serverName] = index
		}

		switch record.RType {
		case A:
			serverAddr, err := netip.ParseAddr(ipString)
			if err == nil {
				serverList[index].IPv4 = serverAddr
			}
		case AAAA:
			serverAddr, err := netip.ParseAddr(ipString)
			if err == nil {
				serverList[index].IPv6 = serverAddr
			}
		}
		log.Printf("\t--> got NS record: %v", serverList[index])
	}
	return serverList
}
