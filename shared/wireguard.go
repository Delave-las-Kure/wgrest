package shared

import (
	"errors"
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func GetWgDevice(deviceName string) (*wgctrl.Client, *wgtypes.Device, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("failed to init wireguard ipc: %s", err))
	}

	device, err := client.Device(deviceName)

	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("failed to get wireguard device: %s", err))
	}

	return client, device, nil
}
