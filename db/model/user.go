package model

import (
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model

	// Foreighn id
	FID string `gorm:"unique;default:null" json:"fid,omitempty"`

	// Friendly name
	Name string `json:"name,omitempty"`

	Peers []Peer `gorm:"constraint:OnDelete:CASCADE;foreignKey:UserID" json:"peers,omitempty"`
}

func (user *User) FromWgPeer(wgPeer *wgtypes.Peer, device string, privateKey string) {
	dbPeer := Peer{}
	dbPeer.FromWgPeer(wgPeer, device, privateKey)
	user.Peers = []Peer{dbPeer}
}

func (user *User) FromWgPeerConfig(wgPeerConf *wgtypes.PeerConfig) {
	dbPeer := Peer{}
	dbPeer.FromWgPeerConfig(wgPeerConf)
	user.Peers = []Peer{dbPeer}
}
