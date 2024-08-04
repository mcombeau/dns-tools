package dns

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
)

func CreateDNSQuery(domainOrIP string, questionType uint16, reverseQuery bool) (query []byte, err error) {
	if reverseQuery {
		ip := domainOrIP
		questionType = PTR // Question type must be PTR for reverse query
		domainOrIP, err = GetReverseDNSDomain(ip)
		if err != nil {
			return []byte{}, fmt.Errorf("get Reverse DNS Domain from IP address: %w", err)
		}
	}

	message := Message{
		Header: Header{
			Id:            generateRandomID(),
			Flags:         Flags{RecursionDesired: true},
			QuestionCount: 1,
		},
		Questions: []Question{
			{
				Name:   domainOrIP,
				QType:  questionType,
				QClass: IN,
			},
		},
	}

	query, err = EncodeMessage(message)
	if err != nil {
		log.Fatalf("Failed to encode DNS message: %v\n", err)
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
