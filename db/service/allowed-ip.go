package service

import (
	"context"

	"github.com/Delave-las-Kure/wgrest/db/model"
	"github.com/Delave-las-Kure/wgrest/db/typecst"
	"gorm.io/gorm"
)

type FindAllowedIpOpts struct {
	ID uint

	PeerID uint

	IP typecst.DbIP

	IPMask typecst.DbIPMask
}

func DeleteAllowedIp(opts *FindAllowedIpOpts, ctx context.Context, client *gorm.DB) error {
	db := client.WithContext(ctx).Model(&model.AllowedIP{})

	req := findAllowedIpBuilder(opts, db)

	peer := model.Peer{}

	result := req.Unscoped().Delete(&peer)

	return result.Error
}

func DeleteAllowedIps(list *[]model.AllowedIP, ctx context.Context, client *gorm.DB) error {
	for _, el := range *list {
		DeleteAllowedIp(&FindAllowedIpOpts{IP: el.IP, IPMask: el.IPMask}, ctx, client)
	}

	return nil
}

func findAllowedIpBuilder(opts *FindAllowedIpOpts, req *gorm.DB) *gorm.DB {

	if opts.ID != 0 {
		req = req.Where("id = ?", opts.ID)
	}

	if opts.PeerID != 0 {
		req = req.Where("peer_id = ?", opts.PeerID)
	}

	if opts.IP != nil {
		req = req.Where("ip = ?", &opts.IP)
	}

	if opts.IPMask != nil {
		req = req.Where("ip_mask = ?", opts.IPMask)
	}

	return req
}
