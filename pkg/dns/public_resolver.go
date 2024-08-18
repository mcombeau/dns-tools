package dns

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

const defaultDNSPort = 53

// TODO: Instead of only returning the first resolver IP found in
// /etc/resolv.conf, return an array of all of them

// GetDefaultPublicResolver returns the first entry in /etc/resolv.conf
//
// Returns:
// - A string with the IP of the default resolver
func GetDefaultPublicResolver() (server netip.AddrPort, err error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return server, fmt.Errorf("cannot open /etc/resolv.conf: %w", err)
	}
	defer file.Close()

	serverString, err := parseFirstResolvConfServerIP(file)
	if err != nil {
		return server, err
	}

	return IPStringToAddrPort(serverString)
}

func IPStringToAddrPort(ip string) (ipAddrPort netip.AddrPort, err error) {
	ipSplit := strings.Split(ip, ":")

	addr, err := netip.ParseAddr(ipSplit[0])
	if err != nil {
		return ipAddrPort, err
	}
	port := defaultDNSPort
	if len(ipSplit) > 1 {
		port, err = strconv.Atoi(ipSplit[1])
		if err != nil {
			return ipAddrPort, err
		}
	}

	ipAddrPort = netip.AddrPortFrom(addr, uint16(port))
	return ipAddrPort, err
}

func parseFirstResolvConfServerIP(file io.Reader) (ip string, err error) {
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
