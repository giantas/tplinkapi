package tplinkapi

import (
	"strconv"
	"strings"
)

const (
	B Storage = iota
	KB
	MB
	GB
)

type RouterInfo struct {
	Model       string
	Description string
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
