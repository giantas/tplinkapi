package main

import (
	"fmt"
	"net/http"
)

var RequestGetRouterInfo = "[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,4\r\nmodelName\r\ndescription\r\nX_TP_isFD\r\nX_TP_ProductVersion\r\n[ETH_SWITCH#0,0,0,0,0,0#0,0,0,0,0,0]1,1\r\nnumberOfVirtualPorts\r\n[MULTIMODE#0,0,0,0,0,0#0,0,0,0,0,0]2,1\r\nmode\r\n[/cgi/info#0,0,0,0,0,0#0,0,0,0,0,0]3,0\r\n"
var RequestLogout = "[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
var RequestStatistics = "[STAT_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n[STAT_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n"
var RequestAddressReservation = "[LAN_DHCP_STATIC_ADDR#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nenable\r\nchaddr\r\nyiaddr\r\n"
var RequestIpMacBinding = "[ARP_BIND#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\nenable\r\n[ARP_BIND_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n"
var RequestBwControlInfo = "[TC#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n[TC_RULE#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n[LAN_WLAN#0,0,0,0,0,0#0,0,0,0,0,0]2,17\r\nname\r\nStandard\r\nSSID\r\nRegulatoryDomain\r\nPossibleChannels\r\nAutoChannelEnable\r\nChannel\r\nX_TP_Bandwidth\r\nEnable\r\nSSIDAdvertisementEnabled\r\nBeaconType\r\nBasicEncryptionModes\r\nWPAEncryptionModes\r\nIEEE11iEncryptionModes\r\nX_TP_Configuration_Modified\r\nWMMEnable\r\nX_TP_FragmentThreshold\r\n"
var RequestToggleBandwidthControl = "[TC#0,0,0,0,0,0#0,0,0,0,0,0]0,4\r\nenable=%d\r\nlinkType=0\r\nupTotalBW=%d\r\ndownTotalBW=%d\r\n"
var RequestAddBwControlEntry = "[TC_RULE#0,0,0,0,0,0#0,0,0,0,0,0]0,12\r\nenable=1\r\nstartIP=%d\r\nendIP=%d\r\nstartPort=0\r\nendPort=0\r\nprotocol=0\r\nprecedence=5\r\nupMinBW=%d\r\nupMaxBW=%d\r\ndownMinBW=%d\r\ndownMaxBW=%d\r\nflag=1\r\n"
var RequestDeleteBwControlEntry = "[TC_RULE#%d,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
var RequestDeleteDhcpReservation = "[LAN_DHCP_STATIC_ADDR#1,%d,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
var RequestDeleteIpMacBinding = "[ARP_BIND_ENTRY#%d,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
var RequestMakeIpMacBinding = "[ARP_BIND_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nstate=1\r\nip=%d\r\nmac=%s\r\n"
var RequestMakeDhcpReservation = "[LAN_DHCP_STATIC_ADDR#0,0,0,0,0,0#1,0,0,0,0,0]0,3\r\nchaddr=%s\r\nyiaddr=%s\r\nenable=1\r\n"

func GetRouterInfo(service RouterService) (RouterInfo, error) {
	var (
		info RouterInfo
		err  error
	)
	path := service.GetAPIURL("1&1&1&8")
	body, err := service.makeRequest(http.MethodPost, path, RequestGetRouterInfo)
	if err != nil {
		return info, err
	}
	return ParseRouterInfo(body)
}

func GetClientInfo(service RouterService) (Client, error) {
	var (
		client Client
		err    error
	)
	path := service.GetAPIURL("1&1&1&8")
	body, err := service.makeRequest(http.MethodPost, path, RequestGetRouterInfo)
	if err != nil {
		return client, err
	}
	return ParseClient(body)
}

func GetStatistics(service RouterService) (ClientStatistics, error) {
	var (
		stats ClientStatistics
		err   error
	)
	path := service.GetAPIURL("1&5")
	body, err := service.makeRequest(http.MethodPost, path, RequestStatistics)
	if err != nil {
		return stats, err
	}
	return ParseStatistics(body)
}

func GetAddressReservations(service RouterService) ([]ClientReservation, error) {
	reservations := make([]ClientReservation, 0)
	path := service.GetAPIURL("5")
	body, err := service.makeRequest(http.MethodPost, path, RequestAddressReservation)
	if err != nil {
		return reservations, err
	}
	return ParseReservations(body)
}

func GetIpMacBindings(service RouterService) ([]ClientReservation, error) {
	reservations := make([]ClientReservation, 0)
	path := service.GetAPIURL("1&5")
	body, err := service.makeRequest(http.MethodPost, path, RequestIpMacBinding)
	if err != nil {
		return reservations, err
	}
	return ParseIpMacBinding(body)
}

func makeDhcpReservation(service RouterService, client Client) error {
	body := fmt.Sprintf(RequestMakeDhcpReservation, client.Mac, client.IP)
	path := service.GetAPIURL("3")
	_, err := service.makeRequest(http.MethodPost, path, body)
	return err
}

func makeIpMacBinding(service RouterService, client Client) error {
	body := fmt.Sprintf(RequestMakeIpMacBinding, client.IpAsInt(), client.Mac)
	path := service.GetAPIURL("3")
	_, err := service.makeRequest(http.MethodPost, path, body)
	return err
}

func MakeIpAddressReservation(service RouterService, client Client) error {
	err := makeDhcpReservation(service, client)
	if err != nil {
		return err
	}
	return makeIpMacBinding(service, client)
}

func deleteDhcpReservation(service RouterService, macAddress string) error {
	reservations, err := GetAddressReservations(service)
	if err != nil {
		return err
	}
	var id int
	for _, v := range reservations {
		if v.Mac == macAddress {
			id = v.Id
			break
		}
	}
	if id == 0 {
		return fmt.Errorf("reservation not found for ip %s", macAddress)
	} else {
		fmt.Printf("reservation for %s found at %d\n", macAddress, id)
	}

	body := fmt.Sprintf(RequestDeleteDhcpReservation, id)
	path := service.GetAPIURL("4")
	_, err = service.makeRequest(http.MethodPost, path, body)
	return err
}

func deleteIpMacBinding(service RouterService, macAddress string) error {
	reservations, err := GetIpMacBindings(service)
	if err != nil {
		return err
	}
	var id int
	for _, v := range reservations {
		if v.Mac == macAddress {
			id = v.Id
			break
		}
	}
	if id == 0 {
		return fmt.Errorf("binding not found for ip %s", macAddress)
	} else {
		fmt.Printf("binding for %s found at %d\n", macAddress, id)
	}

	body := fmt.Sprintf(RequestDeleteIpMacBinding, id)
	path := service.GetAPIURL("4")
	_, err = service.makeRequest(http.MethodPost, path, body)
	return err
}

func DeleteIpAddressReservation(service RouterService, macAddress string) error {
	err := deleteDhcpReservation(service, macAddress)
	if err != nil {
		return err
	}
	return deleteIpMacBinding(service, macAddress)
}

func GetBandwidthControlDetails(service RouterService) (BandwidthControlDetail, error) {
	var config BandwidthControlDetail
	path := service.GetAPIURL("1&5&5")
	body, err := service.makeRequest(http.MethodPost, path, RequestBwControlInfo)
	if err != nil {
		return config, err
	}
	return ParseBandwidthControlInfo(body)
}

func ToggleBandwidthControl(service RouterService, config BandwidthControlDetail) error {
	enable := 0
	if config.Enabled {
		enable = 3
	}
	body := fmt.Sprintf(RequestToggleBandwidthControl, enable, config.UpTotal, config.DownTotal)
	path := service.GetAPIURL("2")
	_, err := service.makeRequest(http.MethodPost, path, body)
	return err
}

func AddBwControlEntry(service RouterService, entry BandwidthControlEntry) (int, error) {
	startIp, err := ip2Int(entry.StartIp)
	if err != nil {
		return 0, err
	}
	endIp, err := ip2Int(entry.EndIp)
	if err != nil {
		return 0, err
	}
	body := fmt.Sprintf(
		RequestAddBwControlEntry, startIp, endIp, entry.UpMin, entry.UpMax, entry.DownMin, entry.DownMax,
	)
	path := service.GetAPIURL("3")
	res, err := service.makeRequest(http.MethodPost, path, body)
	if err != nil {
		return 0, err
	}
	return GetId(res)
}

func DeleteBwControlEntry(service RouterService, entryId int) error {
	details, err := GetBandwidthControlDetails(service)
	if err != nil {
		return err
	}
	exists := false
	for _, entry := range details.Entries {
		if entry.Id == entryId {
			exists = true
			break
		}
	}
	if !exists {
		return fmt.Errorf("entry with id %d not found", entryId)
	}

	body := fmt.Sprintf(RequestDeleteBwControlEntry, entryId)
	path := service.GetAPIURL("4")
	_, err = service.makeRequest(http.MethodPost, path, body)
	return err
}
