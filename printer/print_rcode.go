package printer

import "github.com/mcombeau/go-dns-tools/dns"

type DNSRCode uint16

var dnsResponseCodeNames = map[uint16]string{
	dns.NOERROR:   "No Error",
	dns.FORMERR:   "Format Error",
	dns.SERVFAIL:  "Server Failure",
	dns.NXDOMAIN:  "Non-Existent Domain",
	dns.NOTIMP:    "Not Implemented",
	dns.REFUSED:   "Query Refused",
	dns.YXDOMAIN:  "Name Exists when it should not",
	dns.YXRRSET:   "RR Set Exists when it should not",
	dns.NXRRSET:   "RR Set that should exist does not",
	dns.NOTAUTH:   "Not Authorized",
	dns.NOTZONE:   "Name not contained in zone",
	dns.DSOTYPENI: "DSO-TYPE Not Implemented",
	dns.BADVERS:   "Bad OPT Version",
	// dns.BADSIG:      "TSIG Signature Failure",
	dns.BADKEY:      "Key not recognized",
	dns.BADTIME:     "Signature out of time window",
	dns.BADMODE:     "Bad TKEY Mode",
	dns.BADNAME:     "Duplicate key name",
	dns.BADALG:      "Algorithm not supported",
	dns.BADTRUNC:    "Bad Truncation",
	dns.BADCOOKIE:   "Bad/missing Server Cookie",
	dns.UNASSIGNED1: "Unassigned",
	dns.UNASSIGNED2: "Unassigned",
	dns.UNASSIGNED3: "Unassigned",
	dns.UNASSIGNED4: "Unassigned",
}

func (rc DNSRCode) String() string {
	if n, ok := dnsResponseCodeNames[uint16(rc)]; ok {
		return n
	}
	return "Unknown"
}
