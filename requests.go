package main

import (
	"fmt"
	"net/http"
)

var GetRouterInfoBody = "[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,4\r\nmodelName\r\ndescription\r\nX_TP_isFD\r\nX_TP_ProductVersion\r\n[ETH_SWITCH#0,0,0,0,0,0#0,0,0,0,0,0]1,1\r\nnumberOfVirtualPorts\r\n[MULTIMODE#0,0,0,0,0,0#0,0,0,0,0,0]2,1\r\nmode\r\n[/cgi/info#0,0,0,0,0,0#0,0,0,0,0,0]3,0\r\n"
var LogoutBody = "[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
var StatisticsBody = "[STAT_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n[STAT_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n"
var RequestAddressReservation = "[LAN_DHCP_STATIC_ADDR#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nenable\r\nchaddr\r\nyiaddr\r\n"
var RequestIpMacBinding = "[ARP_BIND#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\nenable\r\n[ARP_BIND_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n"
var RequestBwControlInfo = "[TC#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n[TC_RULE#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n[LAN_WLAN#0,0,0,0,0,0#0,0,0,0,0,0]2,17\r\nname\r\nStandard\r\nSSID\r\nRegulatoryDomain\r\nPossibleChannels\r\nAutoChannelEnable\r\nChannel\r\nX_TP_Bandwidth\r\nEnable\r\nSSIDAdvertisementEnabled\r\nBeaconType\r\nBasicEncryptionModes\r\nWPAEncryptionModes\r\nIEEE11iEncryptionModes\r\nX_TP_Configuration_Modified\r\nWMMEnable\r\nX_TP_FragmentThreshold\r\n"

func GetRouterInfo(service RouterService) (RouterInfo, error) {
	var (
		info RouterInfo
		err  error
	)
	path := service.GetAPIURL("1&1&1&8")
	body, err := service.makeRequest(http.MethodPost, path, GetRouterInfoBody)
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
	body, err := service.makeRequest(http.MethodPost, path, GetRouterInfoBody)
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
	body, err := service.makeRequest(http.MethodPost, path, StatisticsBody)
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
	body := fmt.Sprintf(
		"[LAN_DHCP_STATIC_ADDR#0,0,0,0,0,0#1,0,0,0,0,0]0,3\r\nchaddr=%s\r\nyiaddr=%s\r\nenable=1\r\n",
		client.Mac, client.IP,
	)
	path := service.GetAPIURL("3")
	_, err := service.makeRequest(http.MethodPost, path, body)
	return err
}

func makeIpMacBinding(service RouterService, client Client) error {
	body := fmt.Sprintf(
		"[ARP_BIND_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nstate=1\r\nip=%d\r\nmac=%s\r\n",
		client.IpAsInt(), client.Mac,
	)
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

	body := fmt.Sprintf("[LAN_DHCP_STATIC_ADDR#1,%d,0,0,0,0#0,0,0,0,0,0]0,0\r\n", id)
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

	body := fmt.Sprintf("[ARP_BIND_ENTRY#%d,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n", id)
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
