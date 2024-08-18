package dns

import (
	"net/netip"
)

const MaxUDPMessageLength = 512

type Server struct {
	Fqdn string
	IPv4 netip.Addr
	IPv6 netip.Addr
}

func (server Server) getValidIPAddress() (ip netip.AddrPort, err error) {
	if server.IPv4.IsValid() {
		return netip.AddrPortFrom(server.IPv4, defaultDNSPort), nil
	} else if server.IPv6.IsValid() {
		return netip.AddrPortFrom(server.IPv6, defaultDNSPort), nil
	} else {
		return ip, ErrInvalidIP
	}
}
