package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	modelNameRegex          = regexp.MustCompile(`modelName\=([\w-]+)\s`)
	descriptionRegex        = regexp.MustCompile(`description\=([\w\-\s]+)\s`)
	clientIpRegex           = regexp.MustCompile(`clientIp\=\"([\d\.]+)\"\;`)
	clientMacRegex          = regexp.MustCompile(`clientMac\=\"([\:\w]+)\"\;`)
	errorRegex              = regexp.MustCompile(`\[error\](\d+)`)
	statisticsRegex         = regexp.MustCompile(`ipAddress\=(\d+)\nmacAddress\=([\w\:]+)\ntotalPkts=\d+\ntotalBytes=(\d+)`)
	addressReservationRegex = regexp.MustCompile(`\[\d+\,(\d+).+\]\d\nenable=(\d)\nchaddr\=([\w\:]+)\nyiaddr\=([\d{1,3}\.]+)\n`)
	ipMacBindingRegex       = regexp.MustCompile(`\[(\d+)\,.+\]\d\nstate=(\d)\nip=(\d+)\nmac=([\w\:]+)`)
	bwControlEntryRegex     = regexp.MustCompile(`\[(\d+)\,.*\]\d\n.+\nenable\=(\d)\nstartIP\=(\d+)\nendIP\=(\d+)\n.+\n.+\n.+\n.+\nupMinBW\=(\d+)\nupMaxBW\=(\d+)\ndownMinBW\=(\d+)\ndownMaxBW\=(\d+)\n`)
	bwControlConfigRegex    = regexp.MustCompile(`enable\=(\d)\nlinkType\=\d\nupTotalBW\=(\d+)\ndownTotalBW\=(\d+)`)
)

type Storage int64

type ClientStatistics []ClientStat

func ParseRouterInfo(body string) (RouterInfo, error) {
	modelName := modelNameRegex.FindStringSubmatch(body)
	description := descriptionRegex.FindStringSubmatch(body)
	info := RouterInfo{
		Model:       modelName[1],
		Description: strings.TrimSpace(description[1]),
	}
	return info, nil
}

func ParseClient(body string) (Client, error) {
	clientIp := clientIpRegex.FindStringSubmatch(body)
	clientMac := clientMacRegex.FindStringSubmatch(body)
	info := Client{
		IP:  clientIp[1],
		Mac: clientMac[1],
	}
	return info, nil
}

func ParseStatistics(body string) (ClientStatistics, error) {
	stats := make(ClientStatistics, 0)
	matches := statisticsRegex.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		ip, err := ipToString(match[1])
		if err != nil {
			return stats, err
		}

		mac := match[2]

		byteString := match[3]
		bytes, err := strconv.Atoi(byteString)
		if err != nil {
			return stats, err
		}

		stat := ClientStat{
			Client: Client{
				IP:  ip,
				Mac: mac,
			},
			Bytes: bytes,
		}
		stats = append(stats, stat)
	}
	return stats, nil
}

func ParseReservations(body string) ([]ClientReservation, error) {
	reservations := make([]ClientReservation, 0)
	matches := addressReservationRegex.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		id, err := strconv.Atoi(match[1])
		if err != nil {
			return reservations, err
		}

		reservation := ClientReservation{
			Id: id,
			Client: Client{
				IP:  match[4],
				Mac: match[3],
			},
			Enabled: match[2] == "1",
		}
		reservations = append(reservations, reservation)
	}

	return reservations, nil
}

func ParseIpMacBinding(body string) ([]ClientReservation, error) {
	reservations := make([]ClientReservation, 0)
	matches := ipMacBindingRegex.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		id, err := strconv.Atoi(match[1])
		if err != nil {
			return reservations, err
		}

		ip, err := ipToString(match[3])
		if err != nil {
			return reservations, err
		}

		reservation := ClientReservation{
			Id: id,
			Client: Client{
				IP:  ip,
				Mac: match[4],
			},
			Enabled: match[2] == "1",
		}
		reservations = append(reservations, reservation)
	}

	return reservations, nil
}

func ParseBandwidthControlInfo(body string) (BandwidthControlDetail, error) {
	var config BandwidthControlDetail
	match := bwControlConfigRegex.FindStringSubmatch(body)
	if len(match) == 0 {
		return config, fmt.Errorf("unable to load config")
	}
	upTotal, err := strconv.Atoi(match[2])
	if err != nil {
		return config, err
	}
	downTotal, err := strconv.Atoi(match[3])
	if err != nil {
		return config, err
	}
	config = BandwidthControlDetail{
		Enabled:   match[1] == "3",
		UpTotal:   upTotal,
		DownTotal: downTotal,
	}

	entries := make([]BandwidthControlEntry, 0)
	matches := bwControlEntryRegex.FindAllStringSubmatch(body, -1)
	for _, match := range matches {
		id, err := strconv.Atoi(match[1])
		if err != nil {
			return config, err
		}
		enabled := match[2] == "1"
		startIp, err := ipToString(match[3])
		if err != nil {
			return config, err
		}
		endIp, err := ipToString(match[4])
		if err != nil {
			return config, err
		}
		upMin, err := strconv.Atoi(match[5])
		if err != nil {
			return config, err
		}
		upMax, err := strconv.Atoi(match[6])
		if err != nil {
			return config, err
		}
		downMin, err := strconv.Atoi(match[7])
		if err != nil {
			return config, err
		}
		downMax, err := strconv.Atoi(match[8])
		if err != nil {
			return config, err
		}
		entry := BandwidthControlEntry{
			Id:      id,
			Enabled: enabled,
			UpMin:   upMin,
			UpMax:   upMax,
			DownMin: downMin,
			DownMax: downMax,
			StartIp: startIp,
			EndIp:   endIp,
		}
		entries = append(entries, entry)
	}
	config.Entries = entries
	return config, err
}

func HasError(body string) error {
	error := errorRegex.FindStringSubmatch(body)
	errorString := strings.TrimSpace(error[1])
	if errorString == "0" {
		return nil
	}
	return fmt.Errorf("error %s", errorString)
}

func ipToString(value string) (string, error) {
	ipInt, err := strconv.Atoi(value)
	if err != nil {
		return "", err
	}
	ip := int2ip(uint32(ipInt))
	return ip.String(), err
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
