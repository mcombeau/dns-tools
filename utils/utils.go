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

func DecodeUint16(data []byte, offset int) uint16 {
	return uint16(data[offset])<<8 | uint16(data[offset+1])
}

func DecodeUint32(data []byte, offset int) uint32 {
	return uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3])
}

func EncodeUint16(value uint16) []byte {
	return []byte{byte(value >> 8), byte(value & 0xFF)}
}
