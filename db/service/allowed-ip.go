package service

import (
	"context"

	"github.com/Delave-las-Kure/wgrest/db/model"
	"gorm.io/gorm"
)

type FindAllowedIpOpts struct {
	ID uint

	PeerID uint
}

func DeleteAllowedIp(opts *FindAllowedIpOpts, ctx context.Context, client *gorm.DB) error {
	db := client.WithContext(ctx).Model(&model.AllowedIP{})

	req := findAllowedIpBuilder(opts, db)

	peer := model.Peer{}

	result := req.Unscoped().Delete(&peer)

	return result.Error
}

func findAllowedIpBuilder(opts *FindAllowedIpOpts, req *gorm.DB) *gorm.DB {

	if opts.ID != 0 {
		req = req.Where("id = ?", opts.ID)
	}

	if opts.PeerID != 0 {
		req = req.Where("peer_id = ?", opts.PeerID)
	}

	return req
}
