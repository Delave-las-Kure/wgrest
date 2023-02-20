package model

import (
	"encoding/base64"
	"net"

	"github.com/samber/lo"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gorm.io/gorm"
)

type Peer struct {
	gorm.Model

	//UserID uint `json:"user_id"`

	//User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`

	// Base64 encoded public key
	PublicKey string `gorm:"uniqueIndex" json:"public_key"`

	PrivateKey string `json:"-"`

	Device string `json:"device"`

	// URL safe base64 encoded public key. It is usefull to use in peers api endpoint.
	UrlSafePublicKey string `json:"url_safe_public_key"`

	// Base64 encoded preshared key
	PresharedKey string `json:"preshared_key"`

	// Peer's allowed ips, it might be any of IPv4 or IPv6 addresses in CIDR notation
	AllowedIps []AllowedIP `gorm:"constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"allowed_ips,omitempty"`

	// Enable peer connection
	Disabled bool `json:"disabled"`
}

func (peer *Peer) FromWgPeer(wgPeer *wgtypes.Peer, device string, privateKey string) {
	peer.PublicKey = wgPeer.PublicKey.String()
	peer.UrlSafePublicKey = base64.URLEncoding.EncodeToString(wgPeer.PublicKey[:])
	peer.PresharedKey = wgPeer.PresharedKey.String()

	if device != "" {
		peer.Device = device
	}

	if privateKey != "" {
		peer.PrivateKey = privateKey
	}

	if wgPeer.AllowedIPs != nil {
		peer.AllowedIps = lo.Map(wgPeer.AllowedIPs, func(ipnet net.IPNet, _ int) AllowedIP {
			ip := AllowedIP{}
			ip.FromIPNet(&ipnet)
			return ip
		})
	}
}

func (peer *Peer) FromWgPeerConfig(wgPeerConf *wgtypes.PeerConfig) []string {
	var fields []string

	peer.PublicKey = wgPeerConf.PublicKey.String()
	fields = append(fields, "PublicKey")

	peer.UrlSafePublicKey = base64.URLEncoding.EncodeToString(wgPeerConf.PublicKey[:])
	fields = append(fields, "UrlSafePublicKey")

	if wgPeerConf.PresharedKey != nil {
		peer.PresharedKey = wgPeerConf.PresharedKey.String()
		fields = append(fields, "PresharedKey")
	}

	if wgPeerConf.AllowedIPs != nil {
		peer.AllowedIps = lo.Map(wgPeerConf.AllowedIPs, func(ipnet net.IPNet, _ int) AllowedIP {
			ip := AllowedIP{}
			ip.FromIPNet(&ipnet)
			return ip
		})
		fields = append(fields, "AllowedIps")
	}

	return fields
}
