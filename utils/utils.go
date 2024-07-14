package utils

/*
parse uint16:
"Concatenate" two bytes in a slice to int16.

Ex.:

data[0]: 0x12:	00010010
data[1]: 0x34:	00110100

uint16(data[0]):	00000000 00010010
uint16(data[1]):	00000000 00110100

uint16(data[0]) << 8:	00010010 00000000
uint16(data[1]):		00000000 00110100
|:						00010010 00110100

hex:					0x12	 0x34		: 0x1234
*/

func parseUint16(data []byte, offset int) uint16 {
	return uint16(data[offset])<<8 | uint16(data[offset+1])
}

func parseUint32(data []byte, offset int) uint32 {
	return uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3])
}

/*
Domain name in DNS encoded with labels, each label prefixed with length:
[7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0]
*/

func parseDomainName(data []byte, offset int) (string, int) {
	var name string
	originalOffset := offset
	for {
		lenLabel := int(data[offset])
		if lenLabel == 0 {
			offset++
			name += "." //for root domain
			break
		}
		if len(name) > 0 {
			name += "."
		}
		name += string(data[offset+1 : offset+1+lenLabel])
		offset += lenLabel + 1
	}
	return name, offset - originalOffset
}
