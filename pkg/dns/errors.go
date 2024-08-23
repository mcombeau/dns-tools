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
	ErrServFailToResolveQuery          = errors.New("failed to resolve DNS query")
	ErrServFailToResolveQueryRefused   = errors.New("failed to resolve DNS query: query refused")
)
