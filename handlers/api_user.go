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

	normalUser, err := models.NewUser(&user, true)

	if err != nil {
		ctx.Logger().Errorf("failed to get wireguard peer: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_error",
			Message: err.Error(),
		})
	}

	return ctx.JSON(http.StatusCreated, normalUser)
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
		ctx.Logger().Errorf("failed to get user: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "db_error",
			Message: err.Error(),
		})
	}

	/////////
	normalUser, err := models.NewUser(user, true)

	if err != nil {
		ctx.Logger().Errorf("failed to get wireguard peer: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_error",
			Message: err.Error(),
		})
	}

	return ctx.JSON(http.StatusOK, normalUser)
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

	normalUsers := []models.User{}

	for _, user := range *users {
		normalUser, err := models.NewUser(&user, true)
		if err == nil {
			normalUsers = append(normalUsers, *normalUser)
		}
	}

	return ctx.JSON(http.StatusOK, models.FindUsersResult{Users: normalUsers, Count: count})
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
	opts.JoinPeers = true
	newUser, err := service.FindUser(*opts, ctxp, db)

	normalUser, err := models.NewUser(newUser, true)

	if err != nil {
		ctx.Logger().Errorf("failed to get wireguard peer: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_error",
			Message: err.Error(),
		})
	}

	return ctx.JSON(http.StatusOK, normalUser)
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
