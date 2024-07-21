package dns

// ------------------- RCODES
type DNSRCode uint16

const (
	NOERROR   uint16 = 0  // No Error [RFC1035]
	FORMERR   uint16 = 1  // Format Error [RFC1035]
	SERVFAIL  uint16 = 2  // Server Failure [RFC1035]
	NXDOMAIN  uint16 = 3  // Non-Existent Domain [RFC1035]
	NOTIMP    uint16 = 4  // Not Implemented [RFC1035]
	REFUSED   uint16 = 5  // Query Refused [RFC1035]
	YXDOMAIN  uint16 = 6  // Name Exists when it should not [RFC2136][RFC6672]
	YXRRSET   uint16 = 7  // RR Set Exists when it should not [RFC2136]
	NXRRSET   uint16 = 8  // RR Set that should exist does not [RFC2136]
	NOTAUTH   uint16 = 9  // Server Not Authoritative for zone [RFC2136]
	NOTZONE   uint16 = 10 // Name not contained in zone [RFC2136]
	DSOTYPENI uint16 = 11 // DSO-TYPE Not Implemented [RFC8490]
	BADVERS   uint16 = 16 // Bad OPT Version [RFC6891]
	// BADSIG      uint16 = 16 // TSIG Signature Failure [RFC8945] // BADVERS more common, so ignoring this for now
	BADKEY    uint16 = 17 // Key not recognized [RFC8945]
	BADTIME   uint16 = 18 // Signature out of time window [RFC8945]
	BADMODE   uint16 = 19 // Bad TKEY Mode [RFC2930]
	BADNAME   uint16 = 20 // Duplicate key name [RFC2930]
	BADALG    uint16 = 21 // Algorithm not supported [RFC2930]
	BADTRUNC  uint16 = 22 // Bad Truncation [RFC8945]
	BADCOOKIE uint16 = 23 // Bad/missing Server Cookie [RFC7873]
	// UNASSIGNED1 uint16 = 12 // Unassigned
	// UNASSIGNED2 uint16 = 13 // Unassigned
	// UNASSIGNED3 uint16 = 14 // Unassigned
	// UNASSIGNED4 uint16 = 15 // Unassigned
)

var dnsResponseCodeNames = map[uint16]string{
	NOERROR:   "NOERROR",
	FORMERR:   "FORMERR",
	SERVFAIL:  "SERVFAIL",
	NXDOMAIN:  "NXDOMAIN",
	NOTIMP:    "NOTIMP",
	REFUSED:   "REFUSEd",
	YXDOMAIN:  "YXDOMAIN",
	YXRRSET:   "YXRRSET",
	NXRRSET:   "NXRRSET",
	NOTAUTH:   "NOTAUTH",
	NOTZONE:   "NOTZONE",
	DSOTYPENI: "DSOTYPENI",
	BADVERS:   "BADVERS",
	// BADSIG:      "BADSIG",
	BADKEY:    "BADKEY",
	BADTIME:   "BADTIME",
	BADMODE:   "BADMODE",
	BADNAME:   "BADNAME",
	BADALG:    "BADALG",
	BADTRUNC:  "BADTRUNC",
	BADCOOKIE: "BADCOOKIE",
	// UNASSIGNED1: "Unassigned",
	// UNASSIGNED2: "Unassigned",
	// UNASSIGNED3: "Unassigned",
	// UNASSIGNED4: "Unassigned",
}

func (responseCode DNSRCode) String() string {
	if n, ok := dnsResponseCodeNames[uint16(responseCode)]; ok {
		return n
	}
	return "UNKNOWN"
}

// ------------------- OPCODES
type DNSOpCode uint16

const (
	QUERY      uint16 = 0 // Query [RFC1035]
	IQUERY     uint16 = 1 // Inverse Query, OBSOLETE [RFC3425]
	STATUS     uint16 = 2 // Status [RFC1035]
	UNASSIGNED uint16 = 3 // Unassigned
	NOTIFY     uint16 = 4 // Notify [RFC1996]
	UPDATE     uint16 = 5 // Update [RFC2136]
	DSO        uint16 = 6 // DNS Stateful Operations (DSO) [RFC8490]
	// 7-15	Unassigned
)

var dnsOperationCodeNames = map[uint16]string{
	QUERY:      "QUERY",
	IQUERY:     "IQUERY",
	STATUS:     "STATUS",
	UNASSIGNED: "UNASSIGNED",
	NOTIFY:     "NOTIFY",
	UPDATE:     "UPDATE",
	DSO:        "DSO",
}

func (opCode DNSOpCode) String() string {
	if n, ok := dnsOperationCodeNames[uint16(opCode)]; ok {
		return n
	}
	return "UNKNOWN"
}
