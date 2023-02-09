package service

import (
	"context"
	"errors"
	"strconv"

	"github.com/Delave-las-Kure/wgrest/db/model"
	"github.com/Delave-las-Kure/wgrest/db/scope/paginatesc"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type FindUserOpts struct {
	ID *uint

	Q string

	Name *string

	FID *string

	JoinPeers bool

	Select []string

	paginatesc.PaginateModel
}

func UpsertUser(user *model.User, ctx context.Context, client *gorm.DB) error {
	result := client.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		UpdateAll: true,
	}).Create(user)

	return result.Error
}

func FindUser(opts FindUserOpts, ctx context.Context, client *gorm.DB) (*model.User, error) {
	db := client.WithContext(ctx).Model(&model.User{})

	req := findUserBuilder(opts, ctx, db)

	user := &model.User{}

	result := req.First(user)

	return user, result.Error
}

func FindUsers(opts FindUserOpts, ctx context.Context, client *gorm.DB) (*[]model.User, int64, error) {
	db := client.WithContext(ctx).Model(&model.User{})

	req := findUserBuilder(opts, ctx, db)

	users := []model.User{}

	var count int64

	result := req.Scopes(
		paginatesc.Paginate(&paginatesc.PaginateModel{Page: opts.Page, PerPage: opts.PerPage}),
	).Find(&users)

	req.Count(&count)

	return &users, count, result.Error
}

func UpdateUser(opts FindUserOpts, user *model.User, ctx context.Context, client *gorm.DB) (*model.User, error) {
	db := client.WithContext(ctx).Model(&model.User{})

	req := findUserBuilder(opts, ctx, db)

	result := req.Updates(user)

	return user, result.Error
}

func DeleteUser(opts FindUserOpts, ctx context.Context, client *gorm.DB) error {
	db := client.WithContext(ctx).Model(&model.User{})

	req := findUserBuilder(opts, ctx, db)

	user := &model.User{}

	result := req.Unscoped().Delete(user)

	return result.Error
}

func GenFindUserOpts(ctx echo.Context) (*FindUserOpts, error) {
	opts := FindUserOpts{}

	userId := ctx.Param("id")

	if userId != "" {
		num, err := strconv.Atoi(userId)
		numu := uint(num)
		if err != nil {
			ctx.Logger().Errorf("params error: id param isn't a number")
			return nil, errors.New("params error: id param isn't a number")
		}

		opts.ID = &numu
	}

	q := ctx.QueryParam("q")

	if q != "" {
		opts.Q = q
	}

	name := ctx.Param("name")

	if name != "" {
		opts.Name = &name
	}

	fid := ctx.Param("fid")

	if fid != "" {
		opts.FID = &fid
	}

	page := ctx.QueryParam("page")

	if page != "" {
		num, err := strconv.Atoi(page)
		if err != nil {
			ctx.Logger().Errorf("params error: page param isn't a number")
			return nil, errors.New("params error: page param isn't a number")
		}

		opts.Page = num
	}

	per_page := ctx.QueryParam("per_page")

	if per_page != "" {
		num, err := strconv.Atoi(per_page)
		if err != nil {
			ctx.Logger().Errorf("params error: per_page param isn't a number")
			return nil, errors.New("params error: per_page param isn't a number")
		}

		opts.PerPage = num
	} else {
		opts.PerPage = 100
	}

	return &opts, nil
}

func NewUser() {

}

func findUserBuilder(opts FindUserOpts, ctx context.Context, req *gorm.DB) *gorm.DB {

	if opts.ID != nil {
		req = req.Where("users.id = ?", *opts.ID)
	}

	if opts.Name != nil {
		req = req.Where("users.name = ?", *opts.Name)
	}

	if opts.FID != nil {
		req = req.Where("users.f_id = ?", *opts.FID)
	}

	if opts.Q != "" {
		req = req.Where("users.name LIKE ? OR users.f_id LIKE ?", "%"+opts.Q+"%", "%"+opts.Q+"%")
	}

	if opts.JoinPeers == true {
		req = req.Preload("Peers.AllowedIps")
	}

	if opts.Select != nil {
		req = req.Select(opts.Select)
	}

	return req
}
