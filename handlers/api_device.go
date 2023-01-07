package handlers

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"

	"github.com/samber/lo"

	"github.com/labstack/echo/v4"
	"github.com/skip2/go-qrcode"
	"github.com/suquant/wgrest/models"
	"github.com/suquant/wgrest/storage"
	"github.com/suquant/wgrest/utils"
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
	var request models.PeerCreateOrUpdateRequest
	if err := ctx.Bind(&request); err != nil {
		return err
	}

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

	if request.AllowedIps == nil && device.Peers != nil {

		peerIps := lo.Map(lo.Filter(device.Peers, func(item wgtypes.Peer, i int) bool {
			if item.AllowedIPs == nil {
				return false
			}

			_, hasIp4 := lo.Find(item.AllowedIPs, func(ip net.IPNet) bool {
				return ip.IP.To4() != nil
			})

			return hasIp4
		}), func(item wgtypes.Peer, i int) net.IPNet {
			iIp, _ := lo.Find(item.AllowedIPs, func(ip net.IPNet) bool {
				return ip.IP.To4() != nil
			})

			return iIp
		})

		sort.SliceStable(peerIps, func(i, j int) bool {
			iIp := peerIps[i]
			jIp := peerIps[j]

			for ind := range iIp.IP {
				if iIp.IP[ind] > jIp.IP[ind] {
					return true
				} else if iIp.IP[ind] < jIp.IP[ind] {
					return false
				}
			}

			return false
		})

		latestIpStr := peerIps[0].IP.String()

		addr, addrErr := netip.ParseAddr(latestIpStr)

		b := addr.String()

		fmt.Println(b)

		if addrErr == nil && addr.Next().IsValid() {
			nextAddr := addr.Next()
			ipArr := nextAddr.As4()
			ip := net.IPv4(ipArr[0], ipArr[1], ipArr[2], ipArr[3])

			peerConf.AllowedIPs = []net.IPNet{{IP: ip.To4(), Mask: net.IPv4Mask(255, 255, 255, 255)}}
		}

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

	return ctx.JSON(http.StatusCreated, models.NewPeer(peer))
}

// DeleteDevice - Delete Device
// @todo: need to be implemented
func (c *WireGuardContainer) DeleteDevice(ctx echo.Context) error {
	return ctx.NoContent(http.StatusNotImplemented)
}

// DeleteDevicePeer - Delete device's peer
func (c *WireGuardContainer) DeleteDevicePeer(ctx echo.Context) error {
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

	return ctx.JSON(http.StatusOK, models.NewPeer(*peer))
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
		result[i] = models.NewPeer(v)
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

	return ctx.JSON(http.StatusOK, models.NewPeer(*peer))
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
