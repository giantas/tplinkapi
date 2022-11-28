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
	return GetSubnetPrefix(cfg.SubnetMask)
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
	IP         string
	Mac        string
	SubnetMask string
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

type InternetAccessControl struct {
	Enabled     bool
	DefaultDeny bool
}

type AccessControlHostType int

const (
	IPRangeHostType AccessControlHostType = iota
	MacAddressHostType
)

type AccessControlHostFormatter interface {
	GetRef() string
}

type AccessControlHost struct {
	Id   int
	Type AccessControlHostType
	ref  string
}

type IPRangeAccessControlHost struct {
	AccessControlHost
	StartIP   string
	EndIP     string
	StartPort int
	EndPort   int
}

func NewIPRangeAccessControlHost(startIP, endIP string, startPort, endPort int) (IPRangeAccessControlHost, error) {
	var host IPRangeAccessControlHost

	if !IsValidIPv4Address(startIP) {
		return host, fmt.Errorf("invalid IPv4 address '%s'", startIP)
	}

	if !IsValidIPv4Address(endIP) {
		return host, fmt.Errorf("invalid IPv4 address '%s'", endIP)
	}

	host = IPRangeAccessControlHost{
		AccessControlHost: AccessControlHost{
			Type: IPRangeHostType,
		},
		StartIP:   startIP,
		EndIP:     endIP,
		StartPort: startPort,
		EndPort:   endPort,
	}
	return host, nil
}

func (host IPRangeAccessControlHost) GetRef() string {
	if host.ref != "" {
		return host.ref
	}

	startIp, _ := Ip2Int(host.StartIP)
	endIp, _ := Ip2Int(host.EndIP)
	res := startIp + endIp
	return fmt.Sprintf("%d%d%d", res, host.StartPort, host.EndPort)
}

type MacAddressAccessControlHost struct {
	AccessControlHost
	Mac string
}

func NewMacAddressAccessControlHost(macAddress string) (MacAddressAccessControlHost, error) {
	var host MacAddressAccessControlHost

	if !IsValidMacAddress(macAddress) {
		return host, fmt.Errorf("invalid mac address '%s'", macAddress)
	}

	host = MacAddressAccessControlHost{
		AccessControlHost: AccessControlHost{
			Type: MacAddressHostType,
		},
		Mac: macAddress,
	}

	return host, nil
}

func (host MacAddressAccessControlHost) GetRef() string {
	if host.ref != "" {
		return host.ref
	}

	ref := strings.ReplaceAll(host.Mac, ":", "")
	return ref
}

type AccessControlHostMap map[AccessControlHostType][]interface{}

type Direction int

const (
	IN Direction = iota
	OUT
)

func GetDirectionFromInt(value int) (Direction, error) {
	switch value {
	case 0:
		return IN, nil
	case 1:
		return OUT, nil
	default:
		var d Direction
		return d, fmt.Errorf("invalid direction value")
	}
}

type Protocol int

const (
	TCP Protocol = iota
	UDP
	ICMP
	ALL
)

func GetProtocolFromInt(value int) (Protocol, error) {
	switch value {
	case 0:
		return TCP, nil
	case 1:
		return UDP, nil
	case 2:
		return ICMP, nil
	case 3:
		return ALL, nil
	default:
		var p Protocol
		return p, fmt.Errorf("invalid protocol value '%d'", value)
	}
}

type AccessControlRule struct {
	Id              int
	Enabled         bool
	RuleName        string
	Protocol        Protocol
	Direction       Direction
	InternalHostRef string
	ExternalHostRef string
	ScheduleRef     string
}

type DhcpConfiguration struct {
	Enabled    bool
	MinAddress string
	MaxAddress string
	SubnetMask string
	DNSServers []string
	LeaseTime  int
	IPAddress  string
}
