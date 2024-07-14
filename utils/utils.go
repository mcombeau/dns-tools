package utils

import (
	"errors"
)

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

func ParseUint16(data []byte, offset int) uint16 {
	return uint16(data[offset])<<8 | uint16(data[offset+1])
}

func ParseUint32(data []byte, offset int) uint32 {
	return uint32(data[offset])<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3])
}

/*
Domain name in DNS encoded with labels, each label prefixed with length:

[7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0]

Domain names are also sometimes compressed, meaning they are declared once
in the questions section and in the answers section there is a pointer to the
question section rather than a duplicate of the domain name.

0x192 (0b11000000) indicates that the following is a pointer, here to the 12th byte
which is right after the header (question section domain name field):

[192, 12]
*/

func DecodeDomainName(data []byte, offset int) (string, int, error) {
	var name string
	originalOffset := offset
	jumped := false
	pointerOffset := 0

	for {
		if offset >= len(data) {
			return "", 0, errors.New("offset out of bounds")
		}

		lenLabel := int(data[offset])

		if lenLabel == 0 {
			offset++
			name += "." // for the root domain
			break
		}
		// check if the first two bits are 1s, indicating a pointer
		if lenLabel&0b11000000 == 0b11000000 {
			if !jumped {
				pointerOffset = offset + 2
			}

			newOffset := int(lenLabel&^0b11000000)<<8 | int(data[offset+1])

			if newOffset >= len(data) {
				return "", 0, errors.New("pointer offset out of bounds")
			}

			offset = newOffset
			jumped = true

		} else {
			offset++

			if len(name) > 0 {
				name += "."
			}

			if offset+lenLabel > len(data) {
				return "", 0, errors.New("label length at offset out of bounds")
			}

			name += string(data[offset : offset+lenLabel])
			offset += lenLabel
		}
	}

	if !jumped {
		return name, offset - originalOffset, nil
	}
	return name, pointerOffset - originalOffset, nil
}
