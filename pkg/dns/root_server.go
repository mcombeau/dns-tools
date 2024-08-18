package dns

import (
	"bufio"
	"io"
	"log"
	"net/netip"
	"strings"
	"sync"
)

var (
	RootServers []Server
	once        sync.Once
)

// InitializeRootServers initializes the RootServers global variable.
// This function should be called once, typically during server startup.
func InitializeRootServers(file io.Reader) (err error) {

	once.Do(func() {
		RootServers, err = ParseRootServerHints(file)
	})

	return err
}

func ParseRootServerHints(file io.Reader) (rootServers []Server, err error) {
	scanner := bufio.NewScanner(file)

	var currentServer Server
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, ";") || len(line) == 0 {
			continue
		}

		fields := strings.Fields(line)

		if len(fields) < 4 {
			continue
		}

		fieldType := GetRecordTypeFromTypeString(fields[2])
		switch fieldType {
		case NS:
			if currentServer.Fqdn != "" && (currentServer.IPv4.IsValid() || currentServer.IPv6.IsValid()) {
				rootServers = append(rootServers, currentServer)
			}
			currentServer = Server{Fqdn: MakeFQDN(fields[3])}
		case A:
			currentServer.IPv4, err = netip.ParseAddr(fields[3])
			if err != nil {
				log.Printf("invalid IP: %s: %v\n", fields[3], err)
				continue
			}
		case AAAA:
			currentServer.IPv6, err = netip.ParseAddr(fields[3])
			if err != nil {
				log.Printf("invalid IP: %s: %v\n", fields[3], err)
				continue
			}
		default:
			continue
		}
	}

	if currentServer.Fqdn != "" && (currentServer.IPv4.IsValid() || currentServer.IPv6.IsValid()) {
		rootServers = append(rootServers, currentServer)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(rootServers) < 1 {
		return nil, ErrNoRootServersFound
	}

	return rootServers, nil
}

// const publicDNSServer = "1.1.1.1:53"
// const numberOfRootServers = 13
//
// var RootServers [numberOfRootServers]string
//
// func FetchRootServers() {
// 	// TODO: Maybe run this periodically to update root servers?
// 	rootServerNames := getRootServerNames()
//
// 	var rootServerIPs [numberOfRootServers]string
// 	var count int
//
// 	for i, serverName := range rootServerNames {
// 		ip, err := resolveWithPublicDNS(serverName)
// 		if err != nil {
// 			log.Printf("failed to resolve IP for server %s: %v", serverName, err)
// 			continue
// 		}
//
// 		rootServerIPs[i] = ip
// 		count++
// 	}
//
// 	if count < 1 {
// 		log.Panic("could not resolve IPs for root servers")
// 	}
//
// 	RootServers = rootServerIPs
// 	log.Printf("fetched root servers: %v", RootServers)
// }
//
// func getRootServerNames() (rootServerNames [numberOfRootServers]string) {
// 	for i := 0; i < numberOfRootServers; i++ {
// 		rootServerNames[i] = fmt.Sprintf("%c.root-servers.net.", 'a'+i)
// 	}
// 	return rootServerNames
// }
//
// func resolveWithPublicDNS(serverName string) (ip string, err error) {
// 	conn, err := net.Dial("udp", publicDNSServer)
// 	if err != nil {
// 		return "", err
// 	}
// 	defer conn.Close()
//
// 	query, err := CreateQuery(serverName, A)
// 	if err != nil {
// 		return "", err
// 	}
//
// 	_, err = conn.Write(query)
// 	if err != nil {
// 		return "", err
// 	}
//
// 	response := [MaxDNSMessageSizeOverUDP]byte{}
// 	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
// 	n, err := conn.Read(response[:])
// 	if err != nil {
// 		return "", err
// 	}
//
// 	decodedResponse, err := DecodeMessage(response[:n])
// 	if err != nil {
// 		return "", err
// 	}
//
// 	ip = decodedResponse.Answers[0].RData.String()
// 	_, err = netip.ParseAddr(ip)
// 	if err != nil {
// 		return "", err
// 	}
//
// 	return ip, nil
// }
