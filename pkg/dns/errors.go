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

func invalidMessageError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidMessage, detail)
}

func invalidDomainNameError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidDomainName, detail)
}

func invalidIPError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidIP, detail)
}

func invalidHeaderError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidHeader, detail)
}

func invalidQuestionError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidQuestion, detail)
}

func invalidRecordDataError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidRecordData, detail)
}

func invalidResourceRecordError(detail string) error {
	return fmt.Errorf("%w: %s", ErrInvalidResourceRecord, detail)
}
