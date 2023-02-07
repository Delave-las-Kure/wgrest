package models

import (
	"github.com/Delave-las-Kure/wgrest/db/model"
	"github.com/Delave-las-Kure/wgrest/shared"
	"github.com/samber/lo"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peer - Information about wireguard peer.
type User struct {
	ID uint `json:"id,omitempty"`

	// Foreighn id
	FID string `json:"fid,omitempty"`

	// Friendly name
	Name string `json:"name,omitempty"`

	Peers []Peer `json:"peers,omitempty"`
}

type FindUsersResult struct {
	Users []User `json:"users,omitempty"`
	Count int64  `json:"count,omitempty"`
}

func NewUser(user *model.User, join bool) (*User, error) {
	mUser := User{
		ID:   user.ID,
		FID:  user.FID,
		Name: user.Name,
	}

	groups := lo.GroupBy(user.Peers, func(peer model.Peer) string {
		return peer.Device
	})

	if join {
		var peers []Peer = []Peer{}

		for _, dbPeers := range groups {
			deviceName := dbPeers[0].Device
			client, device, err := shared.GetWgDevice(deviceName)
			if err != nil {
				return nil, err
			}
			for _, dbPeer := range groups[deviceName] {
				peer, ok := lo.Find(device.Peers, func(peer wgtypes.Peer) bool {
					return peer.PublicKey.String() == dbPeer.PublicKey
				})

				if ok {
					peers = append(peers, NewPeer(peer, deviceName, false))
				}

			}
			client.Close()
		}

		mUser.Peers = peers
	}

	return &mUser, nil
}
