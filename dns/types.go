package dns

type DNSType uint16

const (
	A          uint16 = 1     // IPv4 address [RFC1035]
	NS         uint16 = 2     // Authoritative name server [RFC1035]
	MD         uint16 = 3     // Mail destination (OBSOLETE - use MX) [RFC1035]
	MF         uint16 = 4     // Mail forwarder (OBSOLETE - use MX) [RFC1035]
	CNAME      uint16 = 5     // Canonical name for an alias [RFC1035]
	SOA        uint16 = 6     // Start of a zone of authority [RFC1035]
	MB         uint16 = 7     // Mailbox domain name (EXPERIMENTAL) [RFC1035]
	MG         uint16 = 8     // Mail group member (EXPERIMENTAL) [RFC1035]
	MR         uint16 = 9     // Mail rename domain name (EXPERIMENTAL) [RFC1035]
	NULL       uint16 = 10    // Null RR (EXPERIMENTAL) [RFC1035]
	WKS        uint16 = 11    // Well known service description [RFC1035]
	PTR        uint16 = 12    // Domain name pointer [RFC1035]
	HINFO      uint16 = 13    // Host information [RFC1035]
	MINFO      uint16 = 14    // Mailbox or mail list information [RFC1035]
	MX         uint16 = 15    // Mail exchange [RFC1035]
	TXT        uint16 = 16    // Text strings [RFC1035]
	RP         uint16 = 17    // For Responsible Person [RFC1183]
	AFSDB      uint16 = 18    // For AFS Data Base location [RFC1183][RFC5864]
	X25        uint16 = 19    // For X.25 PSDN address [RFC1183]
	ISDN       uint16 = 20    // For ISDN address [RFC1183]
	RT         uint16 = 21    // For Route Through [RFC1183]
	NSAP       uint16 = 22    // For NSAP address, NSAP style A record (DEPRECATED) [RFC1706][status-change-int-tlds-to-historic]
	NSAPPTR    uint16 = 23    // For domain name pointer, NSAP style (DEPRECATED) [RFC1706][status-change-int-tlds-to-historic]
	SIG        uint16 = 24    // For security signature [RFC2536][RFC2931][RFC3110][RFC4034]
	KEY        uint16 = 25    // For security key [RFC2536][RFC2539][RFC3110][RFC4034]
	PX         uint16 = 26    // X.400 mail mapping information [RFC2163]
	GPOS       uint16 = 27    // Geographical Position [RFC1712]
	AAAA       uint16 = 28    // IP6 Address [RFC3596]
	LOC        uint16 = 29    // Location Information [RFC1876]
	NXT        uint16 = 30    // Next Domain (OBSOLETE) [RFC2535][RFC3755]
	EID        uint16 = 31    // Endpoint Identifier [Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]
	NIMLOC     uint16 = 32    // Nimrod Locator [Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]
	SRV        uint16 = 33    // Server Selection [RFC2782]
	ATMA       uint16 = 34    // ATM Address [ATM Forum Technical Committee, "ATM Name System, V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]
	NAPTR      uint16 = 35    // Naming Authority Pointer [RFC3403]
	KX         uint16 = 36    // Key Exchanger [RFC2230]
	CERT       uint16 = 37    // CERT [RFC4398]
	A6         uint16 = 38    // A6 (OBSOLETE - use AAAA) [RFC2874][RFC3226][RFC6563]
	DNAME      uint16 = 39    // DNAME [RFC6672]
	SINK       uint16 = 40    // SINK [Donald_E_Eastlake][draft-eastlake-kitchen-sink]
	OPT        uint16 = 41    // OPT [RFC3225][RFC6891]
	APL        uint16 = 42    // APL [RFC3123]
	DS         uint16 = 43    // Delegation Signer [RFC4034]
	SSHFP      uint16 = 44    // SSH Key Fingerprint [RFC4255]
	IPSECKEY   uint16 = 45    // IPSECKEY [RFC4025]
	RRSIG      uint16 = 46    // RRSIG [RFC4034]
	NSEC       uint16 = 47    // NSEC [RFC4034][RFC9077]
	DNSKEY     uint16 = 48    // DNSKEY [RFC4034]
	DHCID      uint16 = 49    // DHCID [RFC4701]
	NSEC3      uint16 = 50    // NSEC3 [RFC5155][RFC9077]
	NSEC3PARAM uint16 = 51    // NSEC3PARAM [RFC5155]
	TLSA       uint16 = 52    // TLSA [RFC6698]
	SMIMEA     uint16 = 53    // S/MIME cert association [RFC8162]
	HIP        uint16 = 55    // Host Identity Protocol [RFC8005]
	NINFO      uint16 = 56    // NINFO [Jim_Reid]
	RKEY       uint16 = 57    // RKEY [Jim_Reid]
	TALINK     uint16 = 58    // Trust Anchor LINK [Wouter_Wijngaards]
	CDS        uint16 = 59    // Child DS [RFC7344]
	CDNSKEY    uint16 = 60    // DNSKEY(s) the Child wants reflected in DS [RFC7344]
	OPENPGPKEY uint16 = 61    // OpenPGP Key [RFC7929]
	CSYNC      uint16 = 62    // Child-To-Parent Synchronization [RFC7477]
	ZONEMD     uint16 = 63    // Message Digest Over Zone Data [RFC8976]
	SVCB       uint16 = 64    // General-purpose service binding [RFC9460]
	HTTPS      uint16 = 65    // SVCB-compatible type for use with HTTP [RFC9460]
	SPF        uint16 = 99    // [RFC7208]
	UINFO      uint16 = 100   // [IANA-Reserved]
	UID        uint16 = 101   // [IANA-Reserved]
	GID        uint16 = 102   // [IANA-Reserved]
	UNSPEC     uint16 = 103   // [IANA-Reserved]
	NID        uint16 = 104   // [RFC6742]
	L32        uint16 = 105   // [RFC6742]
	L64        uint16 = 106   // [RFC6742]
	LP         uint16 = 107   // [RFC6742]
	EUI48      uint16 = 108   // EUI-48 address [RFC7043]
	EUI64      uint16 = 109   // EUI-64 address [RFC7043]
	TKEY       uint16 = 249   // Transaction Key [RFC2930]
	TSIG       uint16 = 250   // Transaction Signature [RFC8945]
	IXFR       uint16 = 251   // Incremental transfer [RFC1995]
	AXFR       uint16 = 252   // Transfer of an entire zone [RFC1035][RFC5936]
	MAILB      uint16 = 253   // Mailbox-related RRs (MB, MG or MR) [RFC1035]
	MAILA      uint16 = 254   // Mail agent RRs (OBSOLETE - see MX) [RFC1035]
	ALL        uint16 = 255   // A request for some or all records the server has available [RFC1035][RFC6895][RFC8482]
	URI        uint16 = 256   // URI [RFC7553]
	CAA        uint16 = 257   // Certification Authority Restriction [RFC8659]
	AVC        uint16 = 258   // Application Visibility and Control [Wolfgang_Riedel]
	DOA        uint16 = 259   // Digital Object Architecture [draft-durand-doa-over-dns]
	AMTRELAY   uint16 = 260   // Automatic Multicast Tunneling Relay [RFC8777]
	RESINFO    uint16 = 261   // Resolver Information as Key/Value Pairs [RFC9606]
	WALLET     uint16 = 262   // Public wallet address [Paul_Hoffman]
	TA         uint16 = 32768 // DNSSEC Trust Authorities [Sam_Weiler][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.]
	DLV        uint16 = 32769 // DNSSEC Lookaside Validation (OBSOLETE) [RFC8749][RFC4431]
)

var DNSTypeNames = map[string]uint16{
	"A":          A,
	"NS":         NS,
	"MD":         MD,
	"MF":         MF,
	"CNAME":      CNAME,
	"SOA":        SOA,
	"MB":         MB,
	"MG":         MG,
	"MR":         MR,
	"NULL":       NULL,
	"WKS":        WKS,
	"PTR":        PTR,
	"HINFO":      HINFO,
	"MINFO":      MINFO,
	"MX":         MX,
	"TXT":        TXT,
	"RP":         RP,
	"AFSDB":      AFSDB,
	"X25":        X25,
	"ISDN":       ISDN,
	"RT":         RT,
	"NSAP":       NSAP,
	"NSAPPTR":    NSAPPTR,
	"SIG":        SIG,
	"KEY":        KEY,
	"PX":         PX,
	"GPOS":       GPOS,
	"AAAA":       AAAA,
	"LOC":        LOC,
	"NXT":        NXT,
	"EID":        EID,
	"NIMLOC":     NIMLOC,
	"SRV":        SRV,
	"ATMA":       ATMA,
	"NAPTR":      NAPTR,
	"KX":         KX,
	"CERT":       CERT,
	"A6":         A6,
	"DNAME":      DNAME,
	"SINK":       SINK,
	"OPT":        OPT,
	"APL":        APL,
	"DS":         DS,
	"SSHFP":      SSHFP,
	"IPSECKEY":   IPSECKEY,
	"RRSIG":      RRSIG,
	"NSEC":       NSEC,
	"DNSKEY":     DNSKEY,
	"DHCID":      DHCID,
	"NSEC3":      NSEC3,
	"NSEC3PARAM": NSEC3PARAM,
	"TLSA":       TLSA,
	"SMIMEA":     SMIMEA,
	"HIP":        HIP,
	"NINFO":      NINFO,
	"RKEY":       RKEY,
	"TALINK":     TALINK,
	"CDS":        CDS,
	"CDNSKEY":    CDNSKEY,
	"OPENPGPKEY": OPENPGPKEY,
	"CSYNC":      CSYNC,
	"ZONEMD":     ZONEMD,
	"SVCB":       SVCB,
	"HTTPS":      HTTPS,
	"SPF":        SPF,
	"UINFO":      UINFO,
	"UID":        UID,
	"GID":        GID,
	"UNSPEC":     UNSPEC,
	"NID":        NID,
	"L32":        L32,
	"L64":        L64,
	"LP":         LP,
	"EUI48":      EUI48,
	"EUI64":      EUI64,
	"TKEY":       TKEY,
	"TSIG":       TSIG,
	"IXFR":       IXFR,
	"AXFR":       AXFR,
	"MAILB":      MAILB,
	"MAILA":      MAILA,
	"*":          ALL,
	"URI":        URI,
	"CAA":        CAA,
	"AVC":        AVC,
	"DOA":        DOA,
	"AMTRELAY":   AMTRELAY,
	"RESINFO":    RESINFO,
	"WALLET":     WALLET,
	"TA":         TA,
	"DLV":        DLV,
}

// GetRecordTypeFromTypeString returns the DNS record type code for a given type string.
//
// Parameters:
//   - dnsType: The string representation of the DNS record type (e.g., "A", "MX").
//
// Returns:
//   - The corresponding uint16 code for the DNS record type. Returns 0 if the type is not found.
func GetRecordTypeFromTypeString(dnsType string) uint16 {
	if n, ok := DNSTypeNames[dnsType]; ok {
		return n
	}
	return 0
}

var dnsTypeNames = map[uint16]string{
	A:          "A",
	NS:         "NS",
	MD:         "MD",
	MF:         "MF",
	CNAME:      "CNAME",
	SOA:        "SOA",
	MB:         "MB",
	MG:         "MG",
	MR:         "MR",
	NULL:       "NULL",
	WKS:        "WKS",
	PTR:        "PTR",
	HINFO:      "HINFO",
	MINFO:      "MINFO",
	MX:         "MX",
	TXT:        "TXT",
	RP:         "RP",
	AFSDB:      "AFSDB",
	X25:        "X25",
	ISDN:       "ISDN",
	RT:         "RT",
	NSAP:       "NSAP",
	NSAPPTR:    "NSAPPTR",
	SIG:        "SIG",
	KEY:        "KEY",
	PX:         "PX",
	GPOS:       "GPOS",
	AAAA:       "AAAA",
	LOC:        "LOC",
	NXT:        "NXT",
	EID:        "EID",
	NIMLOC:     "NIMLOC",
	SRV:        "SRV",
	ATMA:       "ATMA",
	NAPTR:      "NAPTR",
	KX:         "KX",
	CERT:       "CERT",
	A6:         "A6",
	DNAME:      "DNAME",
	SINK:       "SINK",
	OPT:        "OPT",
	APL:        "APL",
	DS:         "DS",
	SSHFP:      "SSHFP",
	IPSECKEY:   "IPSECKEY",
	RRSIG:      "RRSIG",
	NSEC:       "NSEC",
	DNSKEY:     "DNSKEY",
	DHCID:      "DHCID",
	NSEC3:      "NSEC3",
	NSEC3PARAM: "NSEC3PARAM",
	TLSA:       "TLSA",
	SMIMEA:     "SMIMEA",
	HIP:        "HIP",
	NINFO:      "NINFO",
	RKEY:       "RKEY",
	TALINK:     "TALINK",
	CDS:        "CDS",
	CDNSKEY:    "CDNSKEY",
	OPENPGPKEY: "OPENPGPKEY",
	CSYNC:      "CSYNC",
	ZONEMD:     "ZONEMD",
	SVCB:       "SVCB",
	HTTPS:      "HTTPS",
	SPF:        "SPF",
	UINFO:      "UINFO",
	UID:        "UID",
	GID:        "GID",
	UNSPEC:     "UNSPEC",
	NID:        "NID",
	L32:        "L32",
	L64:        "L64",
	LP:         "LP",
	EUI48:      "EUI48",
	EUI64:      "EUI64",
	TKEY:       "TKEY",
	TSIG:       "TSIG",
	IXFR:       "IXFR",
	AXFR:       "AXFR",
	MAILB:      "MAILB",
	MAILA:      "MAILA",
	ALL:        "*",
	URI:        "URI",
	CAA:        "CAA",
	AVC:        "AVC",
	DOA:        "DOA",
	AMTRELAY:   "AMTRELAY",
	RESINFO:    "RESINFO",
	WALLET:     "WALLET",
	TA:         "TA",
	DLV:        "DLV",
}

func (t DNSType) String() string {
	if n, ok := dnsTypeNames[uint16(t)]; ok {
		return n
	}
	return "UNKNOWN"
}
