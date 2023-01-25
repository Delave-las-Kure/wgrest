package model

import (
	"encoding/json"
	"net"

	"github.com/Delave-las-Kure/wgrest/db/typecst"
)

type AllowedIP struct {
	ID     uint `gorm:"primarykey"`
	PeerID uint
	IP     typecst.DbIP     `gorm:"uniqueIndex;not null;type:text"`
	IPMask typecst.DbIPMask `gorm:"type:text"`
}

func (allIP *AllowedIP) FromIPNet(ip *net.IPNet) {
	allIP.IP = typecst.DbIP(ip.IP)
	allIP.IPMask = typecst.DbIPMask(ip.Mask)
}

func (allIP *AllowedIP) ToIPNet() net.IPNet {
	return net.IPNet{
		IP:   net.IP(allIP.IP),
		Mask: net.IPMask(allIP.IPMask),
	}
}

func (u *AllowedIP) MarshalJSON() ([]byte, error) {
	a := net.IPNet{
		IP:   net.IP(u.IP),
		Mask: net.IPMask(u.IPMask),
	}

	return json.Marshal(a.String())
}
