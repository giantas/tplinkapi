package tplinkapi

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
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

	c = LanConfig{
		MinAddress: startAddress.String(),
		MaxAddress: endAddress.String(),
		SubnetMask: cfg.SubnetMask,
	}
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

func (client Client) IpAsInt() uint32 {
	bits := strings.Split(client.IP, ".")

	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	var sum uint32

	sum += uint32(b0) << 24
	sum += uint32(b1) << 16
	sum += uint32(b2) << 8
	sum += uint32(b3)

	return sum
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
