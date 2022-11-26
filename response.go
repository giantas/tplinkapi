package tplinkapi

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	modelRegex               = regexp.MustCompile(`modelName\=([\w-]+)\sdescription\=([\w\-\s]+)\s`)
	routerNetworkInfoRegex   = regexp.MustCompile(`IPInterfaceIPAddress\=(.*)\sIPInterfaceSubnetMask\=(.*)\sX_TP_MACAddress\=(.*)\s`)
	clientRegex              = regexp.MustCompile(`clientIp\=\"([\d\.]+)\"\;\n.+\sclientMac\=\"([\:\w]+)\"\;`)
	lanConfigRegex           = regexp.MustCompile(`minAddress\=([\d+\.]+)\smaxAddress\=([\d+\.]+)\ssubnetMask\=([\d+\.]+)\s`)
	errorRegex               = regexp.MustCompile(`\[error\](\d+)`)
	statisticsRegex          = regexp.MustCompile(`ipAddress\=(\d+)\nmacAddress\=([\w\:]+)\ntotalPkts=\d+\ntotalBytes=(\d+)`)
	addressReservationRegex  = regexp.MustCompile(`\[\d+\,(\d+).+\]\d\nenable=(\d)\nchaddr\=([\w\:]+)\nyiaddr\=([\d{1,3}\.]+)\n`)
	ipMacBindingRegex        = regexp.MustCompile(`\[(\d+)\,.+\]\d\nstate=(\d)\nip=(\d+)\nmac=([\w\:]+)`)
	bwControlEntryRegex      = regexp.MustCompile(`\[(\d+)\,.*\]\d\n.+\nenable\=(\d)\nstartIP\=(\d+)\nendIP\=(\d+)\n.+\n.+\n.+\n.+\nupMinBW\=(\d+)\nupMaxBW\=(\d+)\ndownMinBW\=(\d+)\ndownMaxBW\=(\d+)\n`)
	bwControlConfigRegex     = regexp.MustCompile(`enable\=(\d)\nlinkType\=\d\nupTotalBW\=(\d+)\ndownTotalBW\=(\d+)`)
	getIdRegex               = regexp.MustCompile(`\[(\d+)\,[\,0]+\]`)
	accessControlHostsRegex  = regexp.MustCompile(`\[(\d+)[\,\d+]+\]\d\srefCnt\=\d+\stype\=(\d)\sentryName\=(.*)\sisParentCtrl\=(\d)\smac\=([\w\:]*)\sIPStart\=([\d+\.])\sIPEnd\=([\d+\.])\sportStart\=(\d+)\sportEnd\=(\d+)\s`)
	accessControleRulesRegex = regexp.MustCompile(`\[(\d+)[\,\d]+\]\d\senable\=(\d)\saction\=\d\sruleName\=(.*)\sisParentCtrl=\d\sdirection\=(\d)\sprotocol\=(\d)\ssetAlready\=\d\sinternalHostRef\=(.*)\sexternalHostRef\=(.*)\sscheduleRef\=(.*)\s`)
)

type Storage int

type ClientStatistics []ClientStat

func ParseRouterInfo(body string) (RouterInfo, error) {
	var info RouterInfo
	match := modelRegex.FindStringSubmatch(body)
	if len(match) != 3 {
		return info, fmt.Errorf("invalid data for router info")
	}
	info = RouterInfo{
		Model:       match[1],
		Description: strings.TrimSpace(match[2]),
	}
	return info, nil
}

func ParseRouterNetworkInfo(body string) (Client, error) {
	var client Client
	match := routerNetworkInfoRegex.FindStringSubmatch(body)
	if len(match) != 4 {
		return client, fmt.Errorf("invalid data for router network info")
	}
	client, err := NewClient(match[1], match[3])
	if err != nil {
		return client, err
	}
	client.SubnetMask = match[2]
	return client, nil
}

func ParseClient(body string) (Client, error) {
	var client Client
	match := clientRegex.FindStringSubmatch(body)
	if len(match) != 3 {
		return client, fmt.Errorf("invalid data for router client info")
	}
	client, err := NewClient(match[1], match[2])
	return client, err
}

func ParseLanConfig(body string) (LanConfig, error) {
	var cfg LanConfig
	match := lanConfigRegex.FindStringSubmatch(body)
	if len(match) != 4 {
		return cfg, fmt.Errorf("invalid data for lan config")
	}
	cfg, err := NewLanConfig(match[1], match[2], match[3])
	return cfg, err
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

		client, err := NewClient(ip, mac)
		if err != nil {
			return stats, err
		}
		stat := ClientStat{
			Client: client,
			Bytes:  bytes,
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

		client, err := NewClient(match[4], match[3])
		if err != nil {
			return reservations, err
		}
		reservation := ClientReservation{
			Id:      id,
			Client:  client,
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

		client, err := NewClient(ip, match[4])
		if err != nil {
			return reservations, err
		}

		reservation := ClientReservation{
			Id:      id,
			Client:  client,
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

func ParseBandwidthControlEntry(body string) (BandwidthControlEntry, error) {
	var entry BandwidthControlEntry
	match := bwControlEntryRegex.FindStringSubmatch(body)
	if len(match) != 9 {
		return entry, fmt.Errorf("invalid data for bandwidth control entry")
	}
	id, err := strconv.Atoi(match[1])
	if err != nil {
		return entry, err
	}
	startIp, err := ipToString(match[3])
	if err != nil {
		return entry, err
	}
	endIp, err := ipToString(match[4])
	if err != nil {
		return entry, err
	}
	upMin, err := strconv.Atoi(match[5])
	if err != nil {
		return entry, err
	}
	upMax, err := strconv.Atoi(match[6])
	if err != nil {
		return entry, err
	}
	downMin, err := strconv.Atoi(match[7])
	if err != nil {
		return entry, err
	}
	downMax, err := strconv.Atoi(match[8])
	if err != nil {
		return entry, err
	}

	entry = BandwidthControlEntry{
		Id:      id,
		Enabled: match[2] == "1",
		StartIp: startIp,
		EndIp:   endIp,
		UpMin:   upMin,
		UpMax:   upMax,
		DownMin: downMin,
		DownMax: downMax,
	}
	return entry, err
}

func ParseAccessControlHosts(body string) (AccessControlHostMap, error) {
	hosts := make(AccessControlHostMap)
	matches := accessControlHostsRegex.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		// skip where isParentControl is 1
		if match[4] == "1" {
			continue
		}

		id, err := strconv.Atoi(match[1])
		if err != nil {
			return hosts, err
		}

		typeInt, err := strconv.Atoi(match[2])
		if err != nil {
			return hosts, err
		}

		ref := match[3]
		mac := match[5]
		startIp := match[6]
		endIp := match[7]
		startPort, err := strconv.Atoi(match[8])
		if err != nil {
			return hosts, err
		}
		endPort, err := strconv.Atoi(match[9])
		if err != nil {
			return hosts, err
		}

		if typeInt == int(MacAddressHostType) {
			host, err := NewMacAddressAccessControlHost(mac)
			if err != nil {
				return hosts, err
			}
			host.Id = id
			host.ref = ref

			hosts[host.Type] = append(hosts[host.Type], host)
		} else if typeInt == int(IPRangeHostType) {
			host, err := NewIPRangeAccessControlHost(startIp, endIp, startPort, endPort)
			if err != nil {
				return hosts, err
			}
			host.Id = id
			host.ref = ref

			hosts[host.Type] = append(hosts[host.Type], host)
		} else {
			return hosts, fmt.Errorf("unidentified type '%d'", typeInt)
		}
	}
	return hosts, nil
}

func ParseAccessControlRules(body string) ([]AccessControlRule, error) {
	rules := make([]AccessControlRule, 0)
	matches := accessControleRulesRegex.FindAllStringSubmatch(body, -1)

	for _, match := range matches {
		id, err := strconv.Atoi(match[1])
		if err != nil {
			return rules, err
		}
		enabled := false
		if match[2] == "1" {
			enabled = true
		}

		ruleName := match[3]
		directionInt, err := strconv.Atoi(match[4])
		if err != nil {
			return rules, err
		}
		direction, err := GetDirectionFromInt(directionInt)
		if err != nil {
			return rules, err
		}
		protocolInt, err := strconv.Atoi(match[5])
		if err != nil {
			return rules, err
		}
		protocol, err := GetProtocolFromInt(protocolInt)
		if err != nil {
			return rules, err
		}
		internalHostRef := match[6]
		externalHostRef := match[7]
		scheduleRef := match[8]

		rule := AccessControlRule{
			Id:              id,
			Enabled:         enabled,
			RuleName:        ruleName,
			Direction:       direction,
			Protocol:        protocol,
			InternalHostRef: internalHostRef,
			ExternalHostRef: externalHostRef,
			ScheduleRef:     scheduleRef,
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func GetId(body string) (int, error) {
	matches := getIdRegex.FindStringSubmatch(body)
	if len(matches) == 0 {
		return 0, fmt.Errorf("id not found")
	}
	stringId := matches[1]
	return strconv.Atoi(stringId)
}
