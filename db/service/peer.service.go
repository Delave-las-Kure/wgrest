package service

import (
	"context"

	"github.com/Delave-las-Kure/wgrest/db/model"
	"github.com/Delave-las-Kure/wgrest/db/scope/paginatesc"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type FindPeerOpts struct {
	ID uint

	PublicKey string

	//JoinUser bool

	JoinAllowedIps bool

	Select []string

	paginatesc.PaginateModel
}

func UpsertPeer(peer *model.Peer, ctx context.Context, client *gorm.DB) (*model.Peer, error) {
	result := client.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "public_key"}},
		UpdateAll: true,
	}).Create(peer)

	return peer, result.Error
}

func UpdatePeer(opts FindPeerOpts, peer *model.Peer, ctx context.Context, client *gorm.DB) (*model.Peer, error) {
	db := client.WithContext(ctx).Model(&model.Peer{}).Debug()

	req := findPeerBuilder(opts, db)

	///rewrite
	if peer.AllowedIps != nil && len(peer.AllowedIps) != 0 && peer.AllowedIps[0].ID == 0 {
		fopts := opts
		fopts.Select = nil
		dPeer, err := FindPeer(fopts, ctx, client)
		if err == nil {
			DeleteAllowedIp(&FindAllowedIpOpts{PeerID: dPeer.ID}, ctx, client)
			client.Model(dPeer).Association("AllowedIps").Append(peer.AllowedIps)
		}

	}

	result := req.Updates(peer)

	if result.Error != nil {
		return nil, result.Error
	}

	fnOpts := FindPeerOpts(opts)
	fnOpts.JoinAllowedIps = true
	//fnOpts.JoinUser = true
	fnOpts.Select = nil

	return FindPeer(fnOpts, ctx, client)
}

func FindPeer(opts FindPeerOpts, ctx context.Context, client *gorm.DB) (*model.Peer, error) {
	db := client.WithContext(ctx).Model(&model.Peer{})

	req := findPeerBuilder(opts, db)

	peer := model.Peer{}

	result := req.First(&peer)

	return &peer, result.Error
}

func FindPeers(opts FindPeerOpts, ctx context.Context, client *gorm.DB) (*[]model.Peer, int64, error) {
	db := client.WithContext(ctx).Model(&model.Peer{})

	req := findPeerBuilder(opts, db)

	peers := []model.Peer{}

	var count int64

	result := req.Scopes(
		paginatesc.Paginate(&paginatesc.PaginateModel{Page: opts.Page, PerPage: opts.PerPage}),
	).Find(&peers)

	req.Count(&count)

	return &peers, count, result.Error
}

func DeletePeer(opts FindPeerOpts, ctx context.Context, client *gorm.DB) error {
	db := client.WithContext(ctx).Model(&model.Peer{})

	req := findPeerBuilder(opts, db)

	peer := model.Peer{}

	result := req.Unscoped().Delete(&peer)

	return result.Error
}

func findPeerBuilder(opts FindPeerOpts, req *gorm.DB) *gorm.DB {

	if opts.ID != 0 {
		req = req.Where("id = ?", opts.ID)
	}

	if opts.PublicKey != "" {
		req = req.Where("public_key = ?", opts.PublicKey)
	}

	if opts.JoinAllowedIps {
		req = req.Preload("AllowedIps")
	}

	/*if opts.JoinUser {
		req = req.Preload("User")
	}*/

	if opts.Select != nil {
		req = req.Select(opts.Select)
	}

	return req
}
