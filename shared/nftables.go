package shared

import (
	"fmt"
	"net"
	"os/exec"
)

const (
	BLACKLIST_TABLE = "blacklist"
	BLACKLIST_CHAIN = "list"
)

// nft add rule nat prerouting iif uplink0 tcp dport 4070 dnat 192.168.23.2:4080

func AddIpToBlacklist(deviceName string, ip net.IPNet) error {
	err := createlacklistTable()

	if err != nil {
		return err
	}

	err = createBlacklistChain(deviceName, ip)

	if err != nil {
		return err
	}

	err = flushlacklistChain(deviceName, ip)

	if err != nil {
		return err
	}

	err = createBlacklistRule(deviceName, ip)

	if err != nil {
		return err
	}

	return nil
}

func RemoveIpFromBlackList(deviceName string, ip net.IPNet) error {
	err := deleteBlacklistChain(deviceName, ip)

	if err != nil {
		return err
	}

	return nil
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

func createTable(family string, tableName string) error {
	cmd := exec.Command("nft", "add", "table", family, tableName)

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func createChain(family string, tableName string, chainName string, st string) error {
	cmd := exec.Command("nft", "add", "chain", family, tableName, chainName, st)

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func createRule(family string, tableName string, chainName string, rule []string) error {

	cmd := exec.Command("nft", append([]string{"add", "rule", family, tableName, chainName}, rule...)...)

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func deleteChain(family string, tableName string, chainName string) error {
	cmd := exec.Command("nft", "delete", "chain", family, tableName, chainName)

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func flushChain(family string, tableName string, chainName string) error {
	cmd := exec.Command("nft", "flush", "chain", family, tableName, chainName)

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func createlacklistTable() error {
	return createTable("inet", BLACKLIST_TABLE)
}

func createBlacklistChain(device string, ip net.IPNet) error {

	return createChain("inet", BLACKLIST_TABLE, getBlacklistChainName(device, ip), "{ type filter hook forward priority filter; policy accept; }")
}

func deleteBlacklistChain(device string, ip net.IPNet) error {

	return deleteChain("inet", BLACKLIST_TABLE, getBlacklistChainName(device, ip))
}

func flushlacklistChain(device string, ip net.IPNet) error {

	return flushChain("inet", BLACKLIST_TABLE, getBlacklistChainName(device, ip))
}

func createBlacklistRule(device string, ip net.IPNet) error {
	cm := "ip"
	if ip.IP.To4() == nil {
		cm = "ip6"
	}
	err := createRule("inet", BLACKLIST_TABLE, getBlacklistChainName(device, ip), []string{"oifname", device, cm, "daddr", ip.String(), "drop"})
	err = createRule("inet", BLACKLIST_TABLE, getBlacklistChainName(device, ip), []string{"iifname", device, cm, "saddr", ip.String(), "drop"})
	return err
}

func getBlacklistChainName(device string, ip net.IPNet) string {

	return BLACKLIST_CHAIN + "_" + device + "_" + fmt.Sprintf("%v", Hash(ip.String()))
}
