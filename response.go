package tplinkapi

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	modelRegex              = regexp.MustCompile(`modelName\=([\w-]+)\sdescription\=([\w\-\s]+)\s`)
	clientRegex             = regexp.MustCompile(`clientIp\=\"([\d\.]+)\"\;\n.+\sclientMac\=\"([\:\w]+)\"\;`)
	lanConfigRegex          = regexp.MustCompile(`minAddress\=([\d+\.]+)\smaxAddress\=([\d+\.]+)\ssubnetMask\=([\d+\.]+)\s`)
	errorRegex              = regexp.MustCompile(`\[error\](\d+)`)
	statisticsRegex         = regexp.MustCompile(`ipAddress\=(\d+)\nmacAddress\=([\w\:]+)\ntotalPkts=\d+\ntotalBytes=(\d+)`)
	addressReservationRegex = regexp.MustCompile(`\[\d+\,(\d+).+\]\d\nenable=(\d)\nchaddr\=([\w\:]+)\nyiaddr\=([\d{1,3}\.]+)\n`)
	ipMacBindingRegex       = regexp.MustCompile(`\[(\d+)\,.+\]\d\nstate=(\d)\nip=(\d+)\nmac=([\w\:]+)`)
	bwControlEntryRegex     = regexp.MustCompile(`\[(\d+)\,.*\]\d\n.+\nenable\=(\d)\nstartIP\=(\d+)\nendIP\=(\d+)\n.+\n.+\n.+\n.+\nupMinBW\=(\d+)\nupMaxBW\=(\d+)\ndownMinBW\=(\d+)\ndownMaxBW\=(\d+)\n`)
	bwControlConfigRegex    = regexp.MustCompile(`enable\=(\d)\nlinkType\=\d\nupTotalBW\=(\d+)\ndownTotalBW\=(\d+)`)
	getIdRegex              = regexp.MustCompile(`\[(\d+)\,[\,0]+\]`)
)

type Storage int64

type ClientStatistics []ClientStat

func ParseRouterInfo(body string) (RouterInfo, error) {
	var info RouterInfo
	match := modelRegex.FindStringSubmatch(body)
	if len(match) != 3 {
		return info, fmt.Errorf("invalid data for router info")
	}
	client, err := ParseClient(body)
	if err != nil {
		return info, err
	}
	info = RouterInfo{
		Model:       match[1],
		Description: strings.TrimSpace(match[2]),
		Client:      client,
	}
	return info, nil
}

func ParseClient(body string) (Client, error) {
	var client Client
	match := clientRegex.FindStringSubmatch(body)
	if len(match) != 3 {
		return client, fmt.Errorf("invalid data for router client info")
	}
	client = Client{
		IP:  match[1],
		Mac: match[2],
	}
	return client, nil
}

func ParseLanConfig(body string) (LanConfig, error) {
	var cfg LanConfig
	match := lanConfigRegex.FindStringSubmatch(body)
	if len(match) != 4 {
		return cfg, fmt.Errorf("invalid data for lan config")
	}
	cfg = LanConfig{
		MinAddress: match[1],
		MaxAddress: match[2],
		SubnetMask: match[3],
	}
	return cfg, nil
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

func GetId(body string) (int, error) {
	matches := getIdRegex.FindStringSubmatch(body)
	if len(matches) == 0 {
		return 0, fmt.Errorf("id not found")
	}
	stringId := matches[1]
	return strconv.Atoi(stringId)
}
