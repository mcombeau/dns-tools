package decoder

import "errors"

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
