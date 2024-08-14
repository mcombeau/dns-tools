package dns

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func GetDNSResolver(server string, port string) (dnsResolver string, err error) {
	if server == "" {
		server, err = GetDefaultResolver()
		if err != nil {
			return "", fmt.Errorf("error getting default DNS resolver: %w", err)
		}
	}
	return fmt.Sprintf("%s:%s", server, port), nil
}

func GetDefaultResolver() (server string, err error) {
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
