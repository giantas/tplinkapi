package tplinkapi

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

const (
	B Storage = iota
	KB
	MB
	GB
)

type LanConfig struct {
	MinAddress string
	MaxAddress string
	SubnetMask string
}

func NewLanConfig(minAddress, maxAddress, subnetMask string) (LanConfig, error) {
	var (
		cfg LanConfig
		err error
	)
	addresses := []string{minAddress, maxAddress, subnetMask}
	for _, address := range addresses {
		if !IsValidIPv4Address(address) {
			return cfg, fmt.Errorf("invalid IPv4 address %s", address)
		}
	}
	cfg = LanConfig{
		MinAddress: minAddress,
		MaxAddress: maxAddress,
		SubnetMask: subnetMask,
	}
	return cfg, err
}

func (cfg LanConfig) GetPrefix() int {
	ip := net.ParseIP(cfg.SubnetMask)
	addr := ip.To4()
	sz, _ := net.IPv4Mask(addr[0], addr[1], addr[2], addr[3]).Size()
	return sz
}

func (cfg LanConfig) GetIpRange() (LanConfig, error) {
	var c LanConfig
	prefix := cfg.GetPrefix()

	_, ipv4Net, err := net.ParseCIDR(fmt.Sprintf("%s/%d", cfg.MinAddress, prefix))
	if err != nil {
		return c, err
	}

	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	finish := (start & mask) | (mask ^ 0xffffffff)

	startAddress := make(net.IP, 4)
	binary.BigEndian.PutUint32(startAddress, start)

	endAddress := make(net.IP, 4)
	binary.BigEndian.PutUint32(endAddress, finish)

	c, err = NewLanConfig(startAddress.String(), endAddress.String(), cfg.SubnetMask)
	return c, err
}

type RouterInfo struct {
	Model       string
	Description string
	Client
}

type Client struct {
	IP  string
	Mac string
}

func NewClient(ip, mac string) (Client, error) {
	var (
		client Client
		err    error
	)

	if !IsValidMacAddress(mac) {
		return client, fmt.Errorf("invalid mac address '%s'", mac)
	}
	mac = strings.ToUpper(mac)

	if !IsValidIPv4Address(ip) {
		return client, fmt.Errorf("invalid IPv4 address")
	}

	client = Client{
		IP:  ip,
		Mac: mac,
	}
	return client, err
}

func (client Client) IsMulticast() bool {
	return IsMulticast(client.Mac)
}

func (client Client) IpAsInt() uint32 {
	ipInt, err := Ip2Int(client.IP)
	if err != nil {
		ipInt = 0
	}
	return ipInt
}

type ClientStat struct {
	Client
	Bytes int
}

func (stat ClientStat) BytesIn(unit Storage) float64 {
	bytes := float64(stat.Bytes)
	switch unit {
	case KB:
		return bytes / 1_000
	case MB:
		return bytes / 1_000_000
	case GB:
		return bytes / 1_000_000_000
	default:
		return bytes
	}
}

type ClientReservation struct {
	Id int
	Client
	Enabled bool
}

type BandwidthControlEntry struct {
	Id      int
	Enabled bool
	StartIp string
	EndIp   string
	UpMin   int
	UpMax   int
	DownMin int
	DownMax int
}

type BandwidthControlDetail struct {
	Enabled   bool
	UpTotal   int
	DownTotal int
	Entries   []BandwidthControlEntry
}
