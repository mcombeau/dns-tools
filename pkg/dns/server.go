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

func (server Server) getValidIPAddress() (ip netip.Addr, err error) {
	if server.IPv4.IsValid() {
		return server.IPv4, nil
	} else if server.IPv6.IsValid() {
		return server.IPv6, nil
	} else {
		return ip, ErrInvalidIP
	}
}
