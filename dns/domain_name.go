package dns

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

/*
Domain name in DNS encoded with labels, each label prefixed with length:

[7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0]

Domain names are also sometimes compressed, meaning they are declared once
in the questions section and in the answers section there is a pointer to the
question section rather than a duplicate of the domain name.

From RFC1035:
The pointer takes the form of a two octet sequence:

+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| 1  1|                OFFSET                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The first two bits are ones.  This allows a pointer to be distinguished
from a label, since the label must begin with two zero bits because
labels are restricted to 63 octets or less.  (The 10 and 01 combinations
are reserved for future use.)
*/

func decodeDomainName(data []byte, offset int) (string, int, error) {
	var name string
	originalOffset := offset
	jumped := false
	pointerOffset := 0

	for {
		if offset >= len(data) {
			return "", 0, invalidDomainNameError("offset out of bounds")
		}

		labelIndicator := int(data[offset]) // Read the label length or pointer indicator

		if labelIndicator == 0 {
			// we've reached the end of the domain name
			offset++
			name += "." // for the root domain
			break
		}

		if labelIndicator&0b11000000 == 0b11000000 {
			// This label indicator byte is a pointer, not a length
			// This means we have to jump to another part of the message

			// We know this because the first two bits are 1:
			// labelIndicator = 0b11000011
			// mask			  = 0b11000000
			// &			  = 0b11000000

			if !jumped {
				// Save the current offset if we haven't jumped yet
				pointerOffset = offset + 2
			}

			// Calculate the new offset we have to jump to:
			// The pointer consists of two bytes:
			// The first byte has its first two bits set to 11, and the remaining 6 bits are the high-order bits of the 14-bit offset.
			// The second byte contains the low-order bits of the 14-bit offset.

			// labelIndicator	=			11000011
			// mask				= 			11000000
			// &^				= 			00000011
			// << 8				= 00000011	00000000
			// data[offset+1]	= 00000000	10001010
			// |				= 00000011	10001010 <- new offset
			newOffset := int(labelIndicator&^0b11000000)<<8 | int(data[offset+1])

			if newOffset >= len(data) {
				return "", 0, invalidDomainNameError("pointer offset out of bounds")
			}

			offset = newOffset // Perform actual jump
			jumped = true

		} else {
			// Normal label, not a pointer:
			// labelIndicator indicates the length of the label
			offset++

			if len(name) > 0 {
				name += "."
			}

			if offset+labelIndicator > len(data) {
				return "", 0, invalidDomainNameError("label offset out of bounds")
			}

			// Add label to domain name
			name += string(data[offset : offset+labelIndicator])
			offset += labelIndicator // Move to the next label
		}
	}

	if !jumped {
		return name, offset - originalOffset, nil
	}
	return name, pointerOffset - originalOffset, nil
}

func encodeDomainName(buf *bytes.Buffer, name string) {
	labels := strings.Split(name, ".")

	for _, label := range labels {
		if len(label) == 0 {
			continue
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}

	buf.WriteByte(0)
}

// GetReverseDNSDomain returns the reverse DNS domain for the given IP address.
// Supports both IPv4 ("<reversed-ip>.in-addr.arpa.") and IPv6 ("<reversed-nibbles>.ip6.arpa.").
// For example:
//   - IPv4: "192.0.1.2" -> "2.1.0.192.in-addr.arpa."
//   - IPv6: "2001:db8::1" -> "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
//
// Parameters:
//   - ip: The IP address to convert.
//
// Returns:
//   - string: The reverse DNS domain.
//   - error: If the IP address is invalid.
func GetReverseDNSDomain(ip string) (string, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", invalidIPError(ip)
	}

	var reversedDomain string
	if parsedIP.To4() != nil {
		// IPv4 address
		reversedDomain = reverseIPv4(parsedIP)

	} else {
		// IPv6 address
		reversedDomain = reverseIPv6(parsedIP)
	}
	return reversedDomain, nil
}

func reverseIPv4(parsedIP net.IP) string {
	octets := strings.Split(parsedIP.String(), ".")

	for i, j := 0, len(octets)-1; i < j; i, j = i+1, j-1 {
		octets[i], octets[j] = octets[j], octets[i]
	}

	return strings.Join(octets, ".") + ".in-addr.arpa."

}

func reverseIPv6(parsedIP net.IP) string {
	parsedIP = parsedIP.To16()

	// Expand IPv6 in case 0s were omitted (e.g. 2001:db8::1)
	// And append them in reverse order, low to high:

	// ex. parsedIP[i]	= 1100 0101
	// 0xF				= 0000 1111
	// & (= low nibble)	= 0000 0101 <- appended first

	// ex. parsedIP[i]		= 1100 0101
	// >> 4 (= high nibble) = 0000 1100 <- appended second

	nibbles := make([]string, 0, 32)
	for i := len(parsedIP) - 1; i >= 0; i-- {
		nibbles = append(nibbles, fmt.Sprintf("%x.%x", parsedIP[i]&0xF, parsedIP[i]>>4))
	}

	return strings.Join(nibbles, ".") + ".ip6.arpa."
}
