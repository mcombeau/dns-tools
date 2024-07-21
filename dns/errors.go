package dns

import (
	"fmt"
)

var (
	ErrInvalidDomainName     = fmt.Errorf("invalid domain name")
	ErrInvalidIP             = fmt.Errorf("invalid IP")
	ErrInvalidHeader         = fmt.Errorf("invalid header")
	ErrInvalidQuestion       = fmt.Errorf("invalid question")
	ErrInvalidRecordData     = fmt.Errorf("invalid record data")
	ErrInvalidResourceRecord = fmt.Errorf("invalid resource record")
	ErrInvalidMessage        = fmt.Errorf("invalid DNS message")
)

func NewInvalidMessageError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidMessage, detail)
}

func NewInvalidDomainNameError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidDomainName, detail)
}

func NewInvalidIPError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidIP, detail)
}

func NewInvalidHeaderError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidHeader, detail)
}

func NewInvalidQuestionError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidQuestion, detail)
}

func NewInvalidRecordDataError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidRecordData, detail)
}

func NewInvalidResourceRecordError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidResourceRecord, detail)
}
