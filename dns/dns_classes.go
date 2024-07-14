package dns

const (
	IN   uint16 = 1   // the Internet
	CS   uint16 = 2   // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	CH   uint16 = 3   // the CHAOS class
	HS   uint16 = 4   // Hesiod [Dyer 87]
	NONE uint16 = 254 // 0x00FE QCLASS NONE [RFC2136]
	ANY  uint16 = 255 // 0x00FF QCLASS * (ANY) [RFC1035]
)
