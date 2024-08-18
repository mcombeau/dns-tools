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
