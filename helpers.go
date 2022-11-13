package tplinkapi

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strconv"
)

func ipToString(value string) (string, error) {
	ipInt, err := strconv.Atoi(value)
	if err != nil {
		return "", err
	}
	ip := Int2ip(uint32(ipInt))
	return ip.String(), err
}

func Int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func Ip2Int(ipAddress string) (uint32, error) {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return 0, fmt.Errorf("invalid ip address")
	}
	i := big.NewInt(0)
	i.SetBytes(ip)
	return uint32(i.Int64()), nil
}
