package handlers

import (
	"context"
	"net/http"

	"github.com/Delave-las-Kure/wgrest/db/connection"
	"github.com/Delave-las-Kure/wgrest/db/model"
	"github.com/Delave-las-Kure/wgrest/db/service"
	"github.com/Delave-las-Kure/wgrest/models"
	"github.com/Delave-las-Kure/wgrest/shared"
	"github.com/labstack/echo/v4"
)

func (c *WireGuardContainer) CreateUser(ctx echo.Context) error {
	ctxp := context.Background()

	var request models.UserCreateOrUpdateRequest
	user := model.User{}

	if err := ctx.Bind(&request); err != nil {
		return err
	}

	if request.Name != nil {
		user.Name = *request.Name
	}

	if request.FID != nil {
		user.FID = *request.FID
	}

	db, _ := connection.Open()

	err := service.UpsertUser(&user, ctxp, db)

	if err != nil {
		ctx.Logger().Errorf("db error: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "db_error",
			Message: err.Error(),
		})
	}

	return ctx.JSON(http.StatusCreated, user)
}

func (c *WireGuardContainer) FindUser(ctx echo.Context) error {

	ctxp := context.Background()

	opts, err := service.GenFindUserOpts(ctx)
	opts.JoinPeers = true

	if err != nil {
		ctx.Logger().Errorf(err.Error())
		return ctx.JSON(http.StatusNotFound, models.Error{
			Code:    "params_error",
			Message: err.Error(),
		})
	}

	db, _ := connection.Open()

	user, err := service.FindUser(*opts, ctxp, db)

	if err != nil {
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "db_error",
			Message: err.Error(),
		})
	}

	return ctx.JSON(http.StatusOK, user)
}

func (c *WireGuardContainer) FindUsers(ctx echo.Context) error {
	ctxp := context.Background()

	var request models.UserCreateOrUpdateRequest

	opts, err := service.GenFindUserOpts(ctx)

	if err != nil {
		ctx.Logger().Errorf(err.Error())
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "params_error",
			Message: err.Error(),
		})
	}

	opts.JoinPeers = true

	db, _ := connection.Open()

	users, count, err := service.FindUsers(*opts, ctxp, db)

	if err := ctx.Bind(&request); err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, service.FindUsersResult{Users: *users, Count: count})
}

func (c *WireGuardContainer) UpdateUser(ctx echo.Context) error {

	ctxp := context.Background()

	var request models.UserCreateOrUpdateRequest
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	opts, err := service.GenFindUserOpts(ctx)

	if err != nil {
		ctx.Logger().Errorf(err.Error())
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "params_error",
			Message: err.Error(),
		})
	}

	db, _ := connection.Open()

	user, err := service.FindUser(*opts, ctxp, db)

	opts.Select = request.Apply(user)

	user, err = service.UpdateUser(*opts, user, ctxp, db)

	if err != nil {
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "update_error",
			Message: err.Error(),
		})
	}

	opts.Select = nil
	newUser, err := service.FindUser(*opts, ctxp, db)

	return ctx.JSON(http.StatusOK, newUser)
}

func (c *WireGuardContainer) DeleteUser(ctx echo.Context) error {

	ctxp := context.Background()

	opts, err := service.GenFindUserOpts(ctx)

	if err != nil {
		ctx.Logger().Errorf(err.Error())
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "params_error",
			Message: err.Error(),
		})
	}

	db, err := connection.Open()

	opts.JoinPeers = true

	user, err := service.FindUser(*opts, ctxp, db)

	if err != nil {
		ctx.Logger().Errorf(err.Error())
		return ctx.JSON(http.StatusNotFound, models.Error{
			Code:    "not_found",
			Message: err.Error(),
		})
	}

	opts.JoinPeers = false

	err = service.DeleteUser(*opts, ctxp, db)

	if err != nil {
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "update_error",
			Message: err.Error(),
		})
	}

	if user.Peers != nil {
		for _, peer := range user.Peers {
			if peer.AllowedIps != nil {
				for _, ip := range peer.AllowedIps {
					shared.RemoveIpFromBlackList(peer.Device, ip.ToIPNet())
				}
			}
		}
	}

	return ctx.NoContent(http.StatusNoContent)
}
