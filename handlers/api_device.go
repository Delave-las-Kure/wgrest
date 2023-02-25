package handlers

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/samber/lo"
	"github.com/vishvananda/netlink"

	"github.com/Delave-las-Kure/wgrest/db/connection"
	"github.com/Delave-las-Kure/wgrest/db/model"
	"github.com/Delave-las-Kure/wgrest/db/service"
	"github.com/Delave-las-Kure/wgrest/models"
	"github.com/Delave-las-Kure/wgrest/shared"
	"github.com/Delave-las-Kure/wgrest/storage"
	"github.com/Delave-las-Kure/wgrest/utils"
	"github.com/labstack/echo/v4"
	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var a = 6

// CreateDevice - Create new device
// @todo: need to be implemented
func (c *WireGuardContainer) CreateDevice(ctx echo.Context) error {
	fmt.Printf("%d", a)
	var request models.DeviceCreateOrUpdateRequest
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	return ctx.NoContent(http.StatusNotImplemented)
}

// CreateDevicePeer - Create new device peer
func (c *WireGuardContainer) CreateDevicePeer(ctx echo.Context) error {
	ctxp := context.Background()
	var request models.PeerCreateOrUpdateRequest
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	/*if request.UserID == nil {
		ctx.Logger().Errorf("userId is required parameter")
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_config_error",
			Message: "userId is required parameter",
		})
	}*/

	var privateKey *wgtypes.Key
	peerConf := wgtypes.PeerConfig{}
	if request.PublicKey != nil {
		pubKey, err := wgtypes.ParseKey(*request.PublicKey)
		if err != nil {
			ctx.Logger().Errorf("failed to parse public key: %s", err)
			return ctx.JSON(http.StatusInternalServerError, models.Error{
				Code:    "wireguard_config_error",
				Message: err.Error(),
			})
		}

		peerConf.PublicKey = pubKey
	} else if request.PrivateKey != nil {
		privKey, err := wgtypes.ParseKey(*request.PrivateKey)
		if err != nil {
			ctx.Logger().Errorf("failed to parse private key: %s", err)
			return ctx.JSON(http.StatusInternalServerError, models.Error{
				Code:    "wireguard_config_error",
				Message: err.Error(),
			})
		}

		peerConf.PublicKey = privKey.PublicKey()
		privateKey = &privKey
	} else {
		privKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			ctx.Logger().Errorf("failed to generate private key: %s", err)
			return ctx.JSON(http.StatusInternalServerError, models.Error{
				Code:    "wireguard_config_error",
				Message: err.Error(),
			})
		}

		peerConf.PublicKey = privKey.PublicKey()
		privateKey = &privKey
	}

	name := ctx.Param("name")

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	err = request.Apply(&peerConf)
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "wireguard_config_error",
			Message: err.Error(),
		})
	}

	device, err := client.Device(name)

	if request.AllowedIps == nil &&
		device.Peers != nil &&
		lo.SomeBy(device.Peers, func(p wgtypes.Peer) bool {
			return p.AllowedIPs != nil
		}) {

		addr, addrErr := GetNextPeerIp(device.Peers)

		if addrErr != nil {
			ctx.Logger().Errorf("failed to generate next ip: %s", err)
			return ctx.JSON(http.StatusBadRequest, models.Error{
				Code:    "wireguard_config_error",
				Message: err.Error(),
			})
		}

		peerConf.AllowedIPs = []net.IPNet{addr}

	} else if request.AllowedIps == nil {
		nextNetIp, err := getNextNetIpFromDevice(name)

		if err != nil {
			ctx.Logger().Errorf("failed to generate next ip from device: %s", err)
			return ctx.JSON(http.StatusBadRequest, models.Error{
				Code:    "wireguard_config_error",
				Message: err.Error(),
			})
		}

		peerConf.AllowedIPs = []net.IPNet{nextNetIp}
	}

	if privateKey != nil {
		err := c.storage.WritePeerOptions(peerConf.PublicKey, storage.StorePeerOptions{
			PrivateKey: privateKey.String(),
		})

		if err != nil {
			ctx.Logger().Errorf("failed to save peer options: %s", err)
			return ctx.JSON(http.StatusInternalServerError, models.Error{
				Code:    "wireguard_config_error",
				Message: err.Error(),
			})
		}
	} else if request.PrivateKey != nil {
		// store private key
		err := c.storage.WritePeerOptions(peerConf.PublicKey, storage.StorePeerOptions{
			PrivateKey: *request.PrivateKey,
		})

		if err != nil {
			ctx.Logger().Errorf("failed to save peer's options: %s", err)
			return ctx.JSON(http.StatusInternalServerError, models.Error{
				Code:    "wireguard_peer_error",
				Message: err.Error(),
			})
		}
	}

	//update db
	db, _ := connection.Open()

	dbPeer := model.Peer{
		Device: name,
	}

	if privateKey != nil {
		dbPeer.PrivateKey = privateKey.String()
	} else if request.PrivateKey != nil {
		dbPeer.PrivateKey = *request.PrivateKey
	}

	/*if request.UserID != nil {
		dbPeer.UserID = *request.UserID
	}*/

	dbPeer.FromWgPeerConfig(&peerConf)

	_, err = service.UpsertPeer(&dbPeer, ctxp, db)

	if err != nil {
		ctx.Logger().Errorf("db error: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "db_error",
			Message: err.Error(),
		})
	}

	deviceConf := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			peerConf,
		},
	}

	if err := client.ConfigureDevice(name, deviceConf); err != nil {
		ctx.Logger().Errorf("failed to configure wireguard device(%s): %s", name, err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "wireguard_error",
			Message: err.Error(),
		})
	}

	device, err = client.Device(name)

	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	var peer wgtypes.Peer
	for _, v := range device.Peers {
		if v.PublicKey == peerConf.PublicKey {
			peer = v
			break
		}
	}

	link, err := netlink.LinkByName(device.Name)
	if err == nil {
		for _, ip := range peer.AllowedIPs {
			netlink.RouteAdd(&netlink.Route{
				Dst:       &ip,
				LinkIndex: link.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
			})
		}
	}

	return ctx.JSON(http.StatusCreated, models.NewPeer(peer, device.Name, true))
}

// DeleteDevice - Delete Device
// @todo: need to be implemented
func (c *WireGuardContainer) DeleteDevice(ctx echo.Context) error {
	return ctx.NoContent(http.StatusNotImplemented)
}

// DeleteDevicePeer - Delete device's peer
func (c *WireGuardContainer) DeleteDevicePeer(ctx echo.Context) error {
	name := ctx.Param("name")
	ctxp := context.Background()

	urlSafePubKey, err := url.QueryUnescape(ctx.Param("urlSafePubKey"))
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	pubKey, err := parseUrlSafeKey(urlSafePubKey)
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	device, err := client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	// update db
	db, _ := connection.Open()
	err = service.DeletePeer(service.FindPeerOpts{PublicKey: pubKey.String()}, ctxp, db)

	if err != nil {
		ctx.Logger().Errorf("failed to delete db record: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "db_error",
			Message: err.Error(),
		})
	}

	deviceConf := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: pubKey,
				Remove:    true,
			},
		},
	}

	if err := client.ConfigureDevice(name, deviceConf); err != nil {
		ctx.Logger().Errorf("failed to configure wireguard device(%s): %s", name, err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "wireguard_error",
			Message: err.Error(),
		})
	}

	var peer wgtypes.Peer
	for _, v := range device.Peers {
		if v.PublicKey == pubKey {
			peer = v
			break
		}
	}

	link, err := netlink.LinkByName(device.Name)
	if err == nil {
		for _, ip := range peer.AllowedIPs {
			netlink.RouteDel(&netlink.Route{
				Dst:       &ip,
				LinkIndex: link.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
			})
		}
	}

	if peer.AllowedIPs != nil {
		for _, ip := range peer.AllowedIPs {
			shared.RemoveIpFromBlackList(name, ip)
		}
	}

	return ctx.NoContent(http.StatusNoContent)
}

// GetDevice - Get device info
func (c *WireGuardContainer) GetDevice(ctx echo.Context) error {
	name := ctx.Param("name")

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	device, err := client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	result := models.NewDevice(device)
	if err := applyNetworks(&result); err != nil {
		ctx.Logger().Errorf("failed to get networks for interface %s: %s", result.Name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	return ctx.JSON(http.StatusOK, result)
}

// GetDevicePeer - Get device peer info
func (c *WireGuardContainer) GetDevicePeer(ctx echo.Context) error {
	name := ctx.Param("name")

	urlSafePubKey, err := url.QueryUnescape(ctx.Param("urlSafePubKey"))
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}
	pubKey, err := parseUrlSafeKey(urlSafePubKey)
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	device, err := client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	var peer *wgtypes.Peer
	for _, v := range device.Peers {
		if v.PublicKey == pubKey {
			peer = &v
			break
		}
	}

	if peer == nil {
		return ctx.NoContent(http.StatusNotFound)
	}

	serPeer := models.NewPeer(*peer, device.Name, true)

	return ctx.JSON(http.StatusOK, serPeer)
}

// ListDevicePeers - Peers list
func (c *WireGuardContainer) ListDevicePeers(ctx echo.Context) error {
	name := ctx.Param("name")

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	device, err := client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	filteredPeers := device.Peers
	q := ctx.QueryParam("q")
	if q != "" {
		filteredPeers = utils.FilterPeersByQuery(q, filteredPeers)
	}

	sortField := ctx.QueryParam("sort")
	if sortField != "" {
		if err := utils.SortPeersByField(sortField, filteredPeers); err != nil {
			ctx.Logger().Errorf("failed sort paginatedPeers: %s", err)
			return ctx.JSON(http.StatusBadRequest, models.Error{
				Code:    "request_params_error",
				Message: err.Error(),
			})
		}
	}

	paginator, err := getPaginator(ctx, len(filteredPeers))
	if err != nil {
		ctx.Logger().Errorf("failed to init paginator: %s", err)
		return err
	}

	beginIndex := paginator.Offset()
	endIndex := beginIndex + paginator.PerPageNums
	if int64(beginIndex) > paginator.Nums() {
		beginIndex = int(paginator.Nums())
	}
	if int64(endIndex) > paginator.Nums() {
		endIndex = int(paginator.Nums())
	}

	paginatedPeers := filteredPeers[beginIndex:endIndex]
	result := make([]models.Peer, len(paginatedPeers))
	for i, v := range paginatedPeers {
		result[i] = models.NewPeer(v, device.Name, true)
	}

	paginator.Write(ctx.Response())
	return ctx.JSON(http.StatusOK, result)
}

// ListDevices - Devices list
func (c *WireGuardContainer) ListDevices(ctx echo.Context) error {
	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	devices, err := client.Devices()
	if err != nil {
		ctx.Logger().Errorf("failed to get wireguard devices: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}

	paginator, err := getPaginator(ctx, len(devices))
	if err != nil {
		ctx.Logger().Errorf("failed to init paginator: %s", err)
		return err
	}

	beginIndex := paginator.Offset()
	endIndex := beginIndex + paginator.PerPageNums
	if int64(beginIndex) > paginator.Nums() {
		beginIndex = int(paginator.Nums())
	}
	if int64(endIndex) > paginator.Nums() {
		endIndex = int(paginator.Nums())
	}

	filteredDevices := devices[beginIndex:endIndex]
	result := make([]models.Device, len(filteredDevices))
	for i, v := range filteredDevices {
		device := models.NewDevice(v)
		if err := applyNetworks(&device); err != nil {
			ctx.Logger().Errorf("failed to get networks for interface %s: %s", device.Name, err)
			return ctx.JSON(http.StatusInternalServerError, models.Error{
				Code:    "wireguard_device_error",
				Message: err.Error(),
			})
		}

		result[i] = device
	}

	paginator.Write(ctx.Response())
	return ctx.JSON(http.StatusOK, result)
}

// UpdateDevice - Update device
func (c *WireGuardContainer) UpdateDevice(ctx echo.Context) error {
	name := ctx.Param("name")

	var request models.DeviceCreateOrUpdateRequest
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	_, err = client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}
	conf := wgtypes.Config{}
	err = request.Apply(&conf)
	if err != nil {
		ctx.Logger().Errorf("failed to get wireguard device conf: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_config_error",
			Message: err.Error(),
		})
	}

	if err := client.ConfigureDevice(name, conf); err != nil {
		ctx.Logger().Errorf("failed to configure wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_error",
			Message: err.Error(),
		})
	}

	device, err := client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	result := models.NewDevice(device)
	if err := applyNetworks(&result); err != nil {
		ctx.Logger().Errorf("failed to get networks for interface %s: %s", result.Name, err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	return ctx.JSON(http.StatusOK, result)
}

// UpdateDevicePeer - Update device's peer
func (c *WireGuardContainer) UpdateDevicePeer(ctx echo.Context) error {
	ctxb := context.Background()
	name := ctx.Param("name")

	urlSafePubKey, err := url.QueryUnescape(ctx.Param("urlSafePubKey"))
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}
	pubKey, err := parseUrlSafeKey(urlSafePubKey)
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	var request models.PeerCreateOrUpdateRequest
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	client, err := wgctrl.New()
	if err != nil {
		ctx.Logger().Errorf("failed to init wireguard ipc: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_client_error",
			Message: err.Error(),
		})
	}
	defer client.Close()

	_, err = client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	peerConf := wgtypes.PeerConfig{
		PublicKey:         pubKey,
		ReplaceAllowedIPs: true,
		UpdateOnly:        true,
	}
	err = request.Apply(&peerConf)
	if err != nil {
		ctx.Logger().Errorf("failed to apply peer conf: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_config_error",
			Message: err.Error(),
		})
	}

	conf := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{
			peerConf,
		},
	}

	// update db
	db, err := connection.Open()
	if err != nil {
		ctx.Logger().Errorf("failed to open db: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "db_error",
			Message: "failed to open db",
		})
	}

	dbPeer := &model.Peer{
		Device: name,
	}

	if request.PrivateKey != nil {
		dbPeer.PrivateKey = *request.PrivateKey
	}

	fields := dbPeer.FromWgPeerConfig(&peerConf)

	/*if request.UserID != nil {
		dbPeer.UserID = *request.UserID
	}*/

	dbPeer, err = service.UpdatePeer(service.FindPeerOpts{PublicKey: pubKey.String(), Select: fields}, dbPeer, ctxb, db)

	if err != nil {
		ctx.Logger().Errorf("failed to update record db: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "db_error",
			Message: "failed to update",
		})
	}

	if err := client.ConfigureDevice(name, conf); err != nil {
		ctx.Logger().Errorf("failed to configure wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_error",
			Message: err.Error(),
		})
	}

	if request.PrivateKey != nil {
		// store private key
		err := c.storage.WritePeerOptions(peerConf.PublicKey, storage.StorePeerOptions{
			PrivateKey: *request.PrivateKey,
		})

		if err != nil {
			ctx.Logger().Errorf("failed to save peer's options: %s", err)
			return ctx.JSON(http.StatusInternalServerError, models.Error{
				Code:    "wireguard_peer_error",
				Message: err.Error(),
			})
		}
	}

	device, err := client.Device(name)
	if err != nil {
		if os.IsNotExist(err) {
			return ctx.NoContent(http.StatusNotFound)
		}

		ctx.Logger().Errorf("failed to get wireguard device: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	var peer *wgtypes.Peer
	for _, v := range device.Peers {
		if v.PublicKey == pubKey {
			peer = &v
			break
		}
	}

	if peer == nil {
		return ctx.NoContent(http.StatusNotFound)
	}

	return ctx.JSON(http.StatusOK, models.NewPeer(*peer, device.Name, true))
}

func (c *WireGuardContainer) getDevicePeerQuickConfig(ctx echo.Context) (io.Reader, error) {
	name := ctx.Param("name")
	urlSafePubKey, err := url.QueryUnescape(ctx.Param("urlSafePubKey"))
	if err != nil {
		return nil, err
	}

	pubKey, err := parseUrlSafeKey(urlSafePubKey)
	if err != nil {
		return nil, err
	}

	peerOptions, err := c.storage.ReadPeerOptions(pubKey)
	if err != nil {
		return nil, err
	}

	deviceOptions, err := c.storage.ReadDeviceOptions(name)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	if deviceOptions == nil {
		deviceOptions = &c.defaultDeviceOptions
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer client.Close()

	device, err := client.Device(name)
	if err != nil {
		return nil, err
	}

	var peer *wgtypes.Peer
	for _, v := range device.Peers {
		if v.PublicKey == pubKey {
			peer = &v
			break
		}
	}

	if peer == nil {
		return nil, os.ErrNotExist
	}

	quickConf, err := utils.GetPeerQuickConfig(*device, *peer, utils.PeerQuickConfigOptions{
		PrivateKey: &peerOptions.PrivateKey,
		DNSServers: &deviceOptions.DNSServers,
		AllowedIPs: &deviceOptions.AllowedIPs,
		Host:       &deviceOptions.Host,
	})

	if err != nil {
		return nil, err
	}

	return quickConf, nil
}

// GetDevicePeerQuickConfig - Get device peer quick config
func (c *WireGuardContainer) GetDevicePeerQuickConfig(ctx echo.Context) error {
	quickConf, err := c.getDevicePeerQuickConfig(ctx)
	if err != nil {
		ctx.Logger().Errorf("failed to get quick config: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	return ctx.Stream(http.StatusOK, "text/plain", quickConf)
}

// GetDevicePeerQuickConfigQRCodePNG - Get device peer quick config QR code
func (c *WireGuardContainer) GetDevicePeerQuickConfigQRCodePNG(ctx echo.Context) error {
	quickConf, err := c.getDevicePeerQuickConfig(ctx)
	if err != nil {
		ctx.Logger().Errorf("failed to get quick config: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	widthParam := ctx.QueryParam("width")
	if widthParam == "" {
		widthParam = "256"
	}
	width, err := strconv.Atoi(widthParam)
	if err != nil {
		ctx.Logger().Errorf("failed to parse width: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(quickConf); err != nil {
		ctx.Logger().Errorf("failed to reade quick config: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	qrBytes, err := qrcode.Encode(buf.String(), qrcode.Medium, width)
	if err != nil {
		ctx.Logger().Errorf("failed to generate qr code: %s", err)
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	qrBuff := bytes.NewBuffer(qrBytes)
	return ctx.Stream(http.StatusOK, "image/png", qrBuff)
}

// GetDeviceOptions - Get device options
func (c *WireGuardContainer) GetDeviceOptions(ctx echo.Context) error {
	options, err := c.storage.ReadDeviceOptions(ctx.Param("name"))
	if err != nil && !os.IsNotExist(err) {
		ctx.Logger().Errorf("failed to get device options: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	if options == nil {
		options = &c.defaultDeviceOptions
	}

	return ctx.JSON(http.StatusOK, models.NewDeviceOptions(*options))
}

// UpdateDeviceOptions - Update device's options
func (c *WireGuardContainer) UpdateDeviceOptions(ctx echo.Context) error {
	var request models.DeviceOptionsUpdateRequest
	if err := ctx.Bind(&request); err != nil {
		return err
	}

	options, err := c.storage.ReadDeviceOptions(ctx.Param("name"))
	if err != nil && !os.IsNotExist(err) {
		ctx.Logger().Errorf("failed to get device options: %s", err)
	}

	if options == nil {
		options = &storage.StoreDeviceOptions{}
	}

	ctx.Logger().Printf("request: %+v\n", request)
	ctx.Logger().Printf("options: %+v\n", *options)

	if err := request.Apply(options); err != nil {
		ctx.Logger().Errorf("failed to update device options: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	err = c.storage.WriteDeviceOptions(ctx.Param("name"), *options)
	if err != nil {
		ctx.Logger().Errorf("failed to save device options: %s", err)
		return ctx.JSON(http.StatusInternalServerError, models.Error{
			Code:    "wireguard_device_error",
			Message: err.Error(),
		})
	}

	return ctx.JSON(http.StatusOK, models.NewDeviceOptions(*options))
}

func (c *WireGuardContainer) DisableDevicePeer(ctx echo.Context) error {
	ctxb := context.Background()
	name := ctx.Param("name")

	db, _ := connection.Open()

	pubKey, err := getPubKey(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	peer, err := service.FindPeer(service.FindPeerOpts{PublicKey: pubKey.String(), JoinAllowedIps: true}, ctxb, db)
	peer.Disabled = true

	_, err = service.UpdatePeer(service.FindPeerOpts{PublicKey: pubKey.String()}, peer, ctxb, db)

	for _, ip := range peer.AllowedIps {
		err := shared.AddIpToBlacklist(name, ip.ToIPNet())
		if err != nil {
			ctx.Logger().Errorf("failed to disable peer: %s", err)
			/*return ctx.JSON(http.StatusBadRequest, models.Error{
				Code:    "disabled_failed",
				Message: "disable failed",
			})*/
		}
	}

	return ctx.NoContent(http.StatusNoContent)
}

func (c *WireGuardContainer) EnableDevicePeer(ctx echo.Context) error {
	ctxb := context.Background()
	name := ctx.Param("name")

	db, _ := connection.Open()

	pubKey, err := getPubKey(ctx)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, models.Error{
			Code:    "request_params_error",
			Message: err.Error(),
		})
	}

	peer, err := service.FindPeer(service.FindPeerOpts{PublicKey: pubKey.String(), JoinAllowedIps: true}, ctxb, db)
	peer.Disabled = false

	_, err = service.UpdatePeer(service.FindPeerOpts{PublicKey: pubKey.String(), Select: []string{"Disabled"}}, peer, ctxb, db)

	for _, ip := range peer.AllowedIps {
		shared.RemoveIpFromBlackList(name, ip.ToIPNet())
		if err != nil {
			ctx.Logger().Errorf("failed to enable peer: %s", err)
			/*return ctx.JSON(http.StatusBadRequest, models.Error{
				Code:    "enable_failed",
				Message: "enable failed",
			})*/
		}
	}

	return ctx.NoContent(http.StatusNoContent)
}
