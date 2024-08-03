package dns

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

func encodeUint16(value uint16) []byte {
	return []byte{byte(value >> 8), byte(value & 0xFF)}
}

func encodeUint32(value uint32) []byte {
	return []byte{
		byte(value >> 24),
		byte((value >> 16) & 0xFF),
		byte((value >> 8) & 0xFF),
		byte(value & 0xFF),
	}
}
