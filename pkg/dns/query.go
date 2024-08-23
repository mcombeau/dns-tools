package dns

import (
	"crypto/rand"
	"fmt"
	"io"
)

// CreateQuery creates a DNS query.
//
// Parameters:
//   - fqdn: the fully qualified domain name for the question section
//   - questionType: a uint16 representing the desired record (A, AAAA, CNAME, etc)
//
// Returns:
//   - query: a byte slice containing the encoded query
//   - error: if there is an error during encoding
func CreateQuery(fqdn string, questionType uint16) (query []byte, err error) {
	message := Message{
		Header: Header{
			Id:            generateRandomID(),
			Flags:         Flags{RecursionDesired: true},
			QuestionCount: 1,
		},
		Questions: []Question{
			{
				Name:   fqdn,
				QType:  questionType,
				QClass: IN,
			},
		},
	}

	query, err = EncodeMessage(message)
	if err != nil {
		return nil, fmt.Errorf("encoding error: %w", err)
	}

	return query, nil
}

func generateRandomID() uint16 {
	bytes := [2]byte{}

	_, err := io.ReadFull(rand.Reader, bytes[:])
	if err != nil {
		panic(err)
	}

	return uint16(bytes[0])<<8 | uint16(bytes[1])
}
