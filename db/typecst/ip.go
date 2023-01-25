package typecst

import (
	"database/sql/driver"
	"errors"
	"net"

	"github.com/Delave-las-Kure/wgrest/shared"
)

type DbIP net.IP

type A struct {
	Data string
}

// Value - Implementation of valuer for database/sql
func (ip DbIP) Value() (driver.Value, error) {
	// value needs to be a base driver.Value type
	// such as bool
	if ip == nil {
		return nil, nil
	}

	ser, err := shared.BytesToBitString(ip)

	if err != nil {
		return nil, nil
	}

	return ser, nil
}

// Scan - Implement the database/sql scanner interface
func (ip *DbIP) Scan(value interface{}) error {
	// if value is nil, false
	if value == nil {
		// set the value of the pointer yne to YesNoEnum(false)
		*ip = DbIP{}
		return nil
	}

	if bv, ok := value.(string); ok == true {
		bytes, err := shared.BitStringToBytes(bv)

		if err != nil {
			*ip = DbIP{}
			return nil
		}

		*ip = DbIP(bytes)

		return nil

	}
	// otherwise, return an error
	return errors.New("failed to scan DbIP")
}
