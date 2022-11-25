package tplinkapi

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"strconv"
)

var macAddressRegex = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)

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

func IsValidMacAddress(value string) bool {
	return macAddressRegex.MatchString(value)
}

func IsMulticast(mac string) bool {
	bin := stringToBin(mac[:2])
	lastBit := bin[len(bin)-1:]
	return lastBit == "1"
}

func IsValidIPv4Address(value string) bool {
	ip := net.ParseIP(value)
	if ip == nil {
		return false
	}
	if ip.To4() == nil {
		return false
	}
	return true
}

func stringToBin(s string) (binString string) {
	for _, c := range s {
		binString = fmt.Sprintf("%s%b", binString, c)
	}
	return
}
