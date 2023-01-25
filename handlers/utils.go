package handlers

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"

	"github.com/Delave-las-Kure/wgrest/models"
	"github.com/Delave-las-Kure/wgrest/utils"
	"github.com/labstack/echo/v4"
	"github.com/samber/lo"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func getPaginator(ctx echo.Context, nums int) (*utils.Paginator, error) {
	perPageParam := ctx.QueryParam("per_page")
	var perPage int = 100

	if perPageParam != "" {
		parsedPerPage, err := strconv.Atoi(perPageParam)
		if err != nil {
			return nil, &echo.HTTPError{
				Code:     http.StatusBadRequest,
				Message:  "failed to parse per_page param",
				Internal: err,
			}
		}

		perPage = parsedPerPage
	}

	return utils.NewPaginator(ctx.Request(), perPage, nums), nil
}

func parseUrlSafeKey(encodedKey string) (wgtypes.Key, error) {
	decodedKey, err := base64.URLEncoding.DecodeString(encodedKey)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("failed to parse key: %s", err)
	}

	if len(decodedKey) != wgtypes.KeyLen {
		return wgtypes.Key{}, fmt.Errorf("failed to parse key: wrong length")
	}
	var key wgtypes.Key
	copy(key[:32], decodedKey[:])

	return key, nil
}

func applyNetworks(device *models.Device) error {
	addresses, err := utils.GetInterfaceIPs(device.Name)
	if err != nil {
		return err
	}

	device.Networks = addresses
	return nil
}

func GetNextPeerIp(peers []wgtypes.Peer) (net.IPNet, error) {
	peerIps := lo.Map(lo.Filter(peers, func(item wgtypes.Peer, i int) bool {
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

	if addrErr == nil && addr.Next().IsValid() {
		nextAddr := addr.Next()
		ipArr := nextAddr.As4()
		ip := net.IPv4(ipArr[0], ipArr[1], ipArr[2], ipArr[3])

		return net.IPNet{IP: ip, Mask: net.IPv4Mask(255, 255, 255, 255)}, nil
	}

	return net.IPNet{}, errors.New("Can't find next ip")
}

func getPubKey(ctx echo.Context) (*wgtypes.Key, error) {

	urlSafePubKey, err := url.QueryUnescape(ctx.Param("urlSafePubKey"))
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return nil, err

	}

	pubKey, err := parseUrlSafeKey(urlSafePubKey)
	if err != nil {
		ctx.Logger().Errorf("failed to parse pub key: %s", err)
		return nil, err
	}

	return &pubKey, nil
}
