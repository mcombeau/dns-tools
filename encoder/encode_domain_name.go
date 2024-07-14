package encoder

import (
	"bytes"
	"strings"
)

func encodeDomainName(buf *bytes.Buffer, name string) {
	parts := strings.Split(name, ".")

	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}

	buf.WriteByte(0)
}
