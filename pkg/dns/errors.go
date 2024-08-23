package dns

import (
	"errors"
)

var (
	ErrInvalidIP                       = errors.New("invalid IP address")
	ErrInvalidLengthTooShort           = errors.New("length too short")
	ErrNoRootServersFound              = errors.New("no root servers found")
	ErrOffsetOutOfBounds               = errors.New("offset out of bounds")
	ErrTooManyPointersCompressedDomain = errors.New("too many pointers in compressed domain")
)
