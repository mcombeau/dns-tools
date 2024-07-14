package printer

import "github.com/mcombeau/go-dns-tools/dns"

type DNSClass uint16

var dnsClassNames = map[uint16]string{
	dns.IN:   "IN",
	dns.CS:   "CS",
	dns.CH:   "CH",
	dns.HS:   "HS",
	dns.NONE: "NONE",
	dns.ANY:  "*",
}

func (c DNSClass) String() string {
	if n, ok := dnsClassNames[uint16(c)]; ok {
		return n
	}
	return "Unknown"
}
