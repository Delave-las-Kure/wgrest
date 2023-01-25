package typecst

import (
	"database/sql/driver"
	"errors"
	"net"

	"github.com/Delave-las-Kure/wgrest/shared"
)

type DbIPMask net.IPMask

// Value - Implementation of valuer for database/sql
func (mask DbIPMask) Value() (driver.Value, error) {
	// value needs to be a base driver.Value type
	// such as bool
	if mask == nil {
		return nil, nil
	}

	ser, err := shared.BytesToBitString(mask)

	if err != nil {
		return nil, nil
	}

	return ser, nil
}

// Scan - Implement the database/sql scanner interface
func (mask *DbIPMask) Scan(value interface{}) error {
	// if value is nil, false
	if value == nil {
		// set the value of the pointer yne to YesNoEnum(false)
		*mask = DbIPMask{}
		return nil
	}

	if bv, ok := value.(string); ok == true {
		bytes, err := shared.BitStringToBytes(bv)

		if err != nil {
			*mask = DbIPMask{}
			return nil
		}

		*mask = DbIPMask(bytes)
		return nil

	}
	// otherwise, return an error
	return errors.New("failed to scan DbIPMask")
}
