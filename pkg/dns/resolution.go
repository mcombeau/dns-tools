package dns

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"
)

type Resolver struct {
	MaxRecursionDepth int
	RootServers       []Server
	NameServerCache   map[string]CachedServer
	AnswerCache       map[string]CachedAnswer
	CacheMutex        sync.RWMutex

	// Query function reference for testing mock injection: default is QueryResponse()
	QueryFunc func(string, netip.AddrPort, []byte) ([]byte, error)
}

// NewResolver creates a resolver structure given a root server hints file
//
// Parameters:
//   - rootServerHintsFilePath: the path to a root server hints file
//
// Returns:
//   - resolver: a pointer to the new resolver structure
//   - err: an error if there was an issue parsing the root server hints file
func NewResolver(rootServerHintsFilePath string) (resolver *Resolver, err error) {
	rootServers, err := getRootServersFromFile(rootServerHintsFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize root servers with file %s: %w", rootServerHintsFilePath, err)
	}

	resolver = &Resolver{
		MaxRecursionDepth: 10,
		RootServers:       rootServers,
		NameServerCache:   make(map[string]CachedServer),
		AnswerCache:       make(map[string]CachedAnswer),
		QueryFunc:         QueryResponse,
	}

	return resolver, nil
}

// ResolveQuery resolves a DNS query by querying servers, starting with the root servers
// until an authoritative answer is found. It may return SERFAIL reply to client if
// there was no satifactory resolution.
//
// Parameters:
//   - rootServers: the list of root servers to start querying
//   - dnsRequest: the request to find an answer for
//
// Returns:
//   - response: the DNS message containing the authoritative answer
//   - err: an error if no response was found
func (resolver *Resolver) ResolveQuery(dnsRequest []byte) (response []byte, err error) {

	dnsParsedRequest, err := DecodeMessage(dnsRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client request: %w", err)
	}

	queryDomain := dnsParsedRequest.Questions[0].Name
	log.Printf("\n-----------------\nQuestion: %s: Start resolution\n-----------------", queryDomain)

	// Check cache before attempting to query servers
	if cachedAnswerRecords, found := resolver.getCachedAnswerRecords(queryDomain); found {
		log.Printf("--> Found cached answer for %s", queryDomain)

		dnsParsedRequest.Header.AnswerRRCount = uint16(len(cachedAnswerRecords))
		dnsParsedRequest.Answers = cachedAnswerRecords

		return EncodeMessage(dnsParsedRequest)
	}

	// TODO: ping root server here to check if it's alive and if not get next root server again?
	rootServer := resolver.GetNextRootServer()

	response, err = resolver.queryServers([]Server{rootServer}, dnsRequest, queryDomain, 0)
	if err != nil {
		if errors.Is(err, ErrServFailToResolveQuery) {
			log.Printf("failed to resolve query, responding with SERVFAIL: %v", err)
			dnsParsedRequest.Header.Flags.ResponseCode = SERVFAIL
			return EncodeMessage(dnsParsedRequest)
		}
		log.Printf("failed to resolve query: %v", err)
		return nil, err
	}

	return response, nil
}

// QueryServers is a recursive function that queries a list of servers until
// it encounters a satisfactory answer from an authoritative nameserver.
// If the response it receives contains to answer but a reference to a nameserver,
// it will attempt to resolve the IP of the nameserver in order to send its
// original query to it.
//
// Parameters:
//   - serverList: a list of servers to query (usually starts with the root servers)
//   - dnsRequest: the request containing the question to resolve
//   - queryDomain: the domain that is being queried for (used for more readable logs)
//   - depth: the current recursion depth
//
// Returns:
//   - response: the response (authoritative) as a slice of bytes
//   - err: an error if an error was encountered (the ErrServFailToResolveQuery error indicates
//     the caller should answer the client with a SERVFAIL message)
func (resolver *Resolver) queryServers(serverList []Server, dnsRequest []byte, queryDomain string, depth int) (response []byte, err error) {

	if depth >= resolver.MaxRecursionDepth {
		return nil, fmt.Errorf("recursion depth exceeded")
	}

	for _, server := range serverList {

		// TODO: If IPv6 doesn't work, fall back to IPv4
		serverAddrPort, err := server.getValidIPAddress()
		if err != nil {
			log.Printf("[depth %d]==> Question: %s: Moving on: server has no valid IP address: %v", depth, queryDomain, err)
			continue
		}

		log.Printf("[depth %d]==> Question: %s: Querying server %s (IP: %v)", depth, queryDomain, server.Fqdn, serverAddrPort)

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
			log.Printf("==>[depth %d] Question: %s: Got authoritative answer from server %s", depth, queryDomain, server)
			for i, answer := range dnsParsedResponse.Answers {
				log.Printf("[depth %d]=============> Question: %s: [ANSWER %d] %s: %s", depth, queryDomain, i, DNSType(answer.RType).String(), answer.RData.String())
				// Cache the authoritative answer
				resolver.cacheAnswerRecord(queryDomain, answer)
			}
			// log.Println("-------------------")
			// PrintMessage(dnsParsedResponse)
			// log.Println("-------------------")

			return response, nil
		}

		if dnsParsedResponse.ContainsAdditionalSectionWithIPAddresses() {
			log.Printf("[depth %d]==> Got additional records response from server %s for %s", depth, server, queryDomain)

			authorityServers := resolver.extractNameServerIPs(dnsParsedResponse.Additionals)

			if len(authorityServers) > 0 {
				return resolver.queryServers(authorityServers, dnsRequest, queryDomain, depth+1)
			} else {
				log.Println("------------------- ADDITIONAL SECTION IS EMPTY?")
				PrintMessage(dnsParsedResponse)
				log.Println("-------------------")
				return nil, fmt.Errorf("%w: could not parse additional section in response from server %s", ErrServFailToResolveQuery, server)
			}
		}

		if dnsParsedResponse.ContainsAuthoritySection() {
			log.Printf("[depth %d]==> Got NS records from server %s for %s", depth, server, queryDomain)

			authorityServers := resolver.resolveNameServerRecords(dnsParsedResponse, server, depth+1)

			if len(authorityServers) > 0 {
				return resolver.queryServers(authorityServers, dnsRequest, queryDomain, depth+1)
			} else {
				log.Println("------------------- AUTHORITY SECTION IS EMPTY?")
				PrintMessage(dnsParsedResponse)
				log.Println("-------------------")
				return nil, fmt.Errorf("%w: could not parse authority section in response from server %s", ErrServFailToResolveQuery, server)
			}
		}
	}

	return nil, fmt.Errorf("%w: break in the chain", ErrServFailToResolveQuery)
}

// resolveNameServerRecords resolves and returns a list of DNS servers for the NS records
// in the provided DNS message. It first checks the cache and then queries the original
// server or root servers if necessary. The function handles recursive queries and
// returns a list of servers with the resolved IP addresses.
func (resolver *Resolver) resolveNameServerRecords(dnsMessage Message, originalServer Server, depth int) (serverList []Server) {
	for _, nameServerRecord := range dnsMessage.NameServers {
		if nameServerRecord.RType == NS {
			nsRecord := nameServerRecord.RData.String()

			// Check cache before attempting to query servers
			if cachedServer, found := resolver.getCachedNameServer(nsRecord); found {
				log.Printf("--> Found cached server for %s: %v", nsRecord, cachedServer)
				serverList = append(serverList, cachedServer)
				continue
			}

			nameServerQuery, err := CreateQuery(nsRecord, A)
			if err != nil {
				continue
			}

			// Query the server the response came from instead of going back up to root
			response, err := resolver.queryServers([]Server{originalServer}, nameServerQuery, nsRecord, depth)
			if err != nil {
				log.Printf("Failed to query original server %v for %s: %v", originalServer, nsRecord, err)

				// If original server refuses the request, query root server
				if err == ErrServFailToResolveQueryRefused {
					rootServer := resolver.GetNextRootServer()

					response, err = resolver.queryServers([]Server{rootServer}, nameServerQuery, nsRecord, depth)
					if err != nil {
						log.Printf("Failed to query root server %v for %s: %v", originalServer, nsRecord, err)
						continue
					}
				}
			}

			parsedResponse, err := DecodeMessage(response)
			if err != nil {
				log.Printf("Failed to decode message from server %v for %s: %v", originalServer, nsRecord, err)
				continue
			}

			log.Printf("--> got response from servers for nsRecord: %s: %s\n", nsRecord, parsedResponse.Answers[0].RData.String())

			serverList = append(serverList, resolver.extractNameServerIPs(parsedResponse.Answers)...)
		}
	}
	return serverList
}

// extractNameServerIPs processes DNS resource records to extract server names and their
// corresponding IPv4 and IPv6 addresses. It caches each name server with its TTL and
// returns a list of Server structs containing the resolved IP addresses.
func (resolver *Resolver) extractNameServerIPs(dnsResourceRecord []ResourceRecord) (serverList []Server) {
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

		// Cache the name server
		ttl := time.Duration(record.TTL) * time.Second
		resolver.cacheNameserver(serverList[index], ttl)
	}

	return serverList
}
