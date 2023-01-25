package shared

import (
	"errors"
	"fmt"
)

func BytesToBitString(arr []byte) (string, error) {
	if arr == nil {
		return "", errors.New("nil bytes array")
	}

	str := ""

	for _, n := range arr {
		str += fmt.Sprintf("%08b", n)
	}

	return str, nil
}

func BitStringToBytes(s string) ([]byte, error) {
	b := make([]byte, (len(s)+(8-1))/8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '1' {
			return nil, errors.New("value out of range")
		}
		b[i>>3] |= (c - '0') << uint(7-i&7)
	}
	return b, nil
}
