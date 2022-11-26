package tplinkapi

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var (
	RequestGetRouterInfo               = "[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,4\r\nmodelName\r\ndescription\r\nX_TP_isFD\r\nX_TP_ProductVersion\r\n[ETH_SWITCH#0,0,0,0,0,0#0,0,0,0,0,0]1,1\r\nnumberOfVirtualPorts\r\n[MULTIMODE#0,0,0,0,0,0#0,0,0,0,0,0]2,1\r\nmode\r\n[/cgi/info#0,0,0,0,0,0#0,0,0,0,0,0]3,0\r\n"
	RequestLanConfig                   = "[LAN_HOST_CFG#1,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n[LAN_IP_INTF#0,0,0,0,0,0#1,0,0,0,0,0]1,4\r\nIPInterfaceIPAddress\r\nIPInterfaceSubnetMask\r\n__ifName\r\nX_TP_MACAddress\r\n[LAN_IGMP_SNOOP#1,0,0,0,0,0#0,0,0,0,0,0]2,1\r\nenabled\r\n"
	RequestLogout                      = "[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
	RequestStatistics                  = "[STAT_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n[STAT_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n"
	RequestAddressReservation          = "[LAN_DHCP_STATIC_ADDR#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nenable\r\nchaddr\r\nyiaddr\r\n"
	RequestIpMacBinding                = "[ARP_BIND#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\nenable\r\n[ARP_BIND_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n"
	RequestBwControlInfo               = "[TC#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n[TC_RULE#0,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n[LAN_WLAN#0,0,0,0,0,0#0,0,0,0,0,0]2,17\r\nname\r\nStandard\r\nSSID\r\nRegulatoryDomain\r\nPossibleChannels\r\nAutoChannelEnable\r\nChannel\r\nX_TP_Bandwidth\r\nEnable\r\nSSIDAdvertisementEnabled\r\nBeaconType\r\nBasicEncryptionModes\r\nWPAEncryptionModes\r\nIEEE11iEncryptionModes\r\nX_TP_Configuration_Modified\r\nWMMEnable\r\nX_TP_FragmentThreshold\r\n"
	RequestToggleBandwidthControl      = "[TC#0,0,0,0,0,0#0,0,0,0,0,0]0,4\r\nenable=%d\r\nlinkType=0\r\nupTotalBW=%d\r\ndownTotalBW=%d\r\n"
	RequestAddBwControlEntry           = "[TC_RULE#0,0,0,0,0,0#0,0,0,0,0,0]0,12\r\nenable=1\r\nstartIP=%d\r\nendIP=%d\r\nstartPort=0\r\nendPort=0\r\nprotocol=0\r\nprecedence=5\r\nupMinBW=%d\r\nupMaxBW=%d\r\ndownMinBW=%d\r\ndownMaxBW=%d\r\nflag=1\r\n"
	RequestDeleteBwControlEntry        = "[TC_RULE#%d,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
	RequestDeleteDhcpReservation       = "[LAN_DHCP_STATIC_ADDR#1,%d,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
	RequestDeleteIpMacBinding          = "[ARP_BIND_ENTRY#%d,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
	RequestMakeIpMacBinding            = "[ARP_BIND_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\nstate=1\r\nip=%d\r\nmac=%s\r\n"
	RequestMakeDhcpReservation         = "[LAN_DHCP_STATIC_ADDR#0,0,0,0,0,0#1,0,0,0,0,0]0,3\r\nchaddr=%s\r\nyiaddr=%s\r\nenable=1\r\n"
	RequestBandwidthControlEntry       = "[TC#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n[TC_RULE#%d,0,0,0,0,0#0,0,0,0,0,0]1,0\r\n"
	RequestToggleInternetAccessControl = "[FIREWALL#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nenable=%d\r\ndefaultAction=%d\r\n"
	RequestDeleteAccessControlHost     = "[INTERNAL_HOST#%d,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n"
	RequestAddAccessControlRule        = "[RULE#0,0,0,0,0,0#0,0,0,0,0,0]0,8\r\nruleName=%s\r\ninternalHostRef=%s\r\nexternalHostRef=\r\nscheduleRef=\r\naction=1\r\nenable=1\r\ndirection=0\r\nprotocol=3\r\n"
)

type RouterService struct {
	Username string
	Password string
	Address  string
}

func (service RouterService) GetAPIURL(params string) string {
	path := service.Address + "/cgi"
	if params != "" {
		path = path + "?" + params
	}
	return path
}

func (service RouterService) basicAuth(username, password string) string {
	auth := fmt.Sprintf("%s:%s", username, password)
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (service RouterService) GetAuthHeader() string {
	return "Basic " + service.basicAuth(service.Username, service.Password)
}

func (service RouterService) GetHeaders() http.Header {
	return http.Header{
		"Accept":          {"*/*"},
		"Accept-Language": {"en-US,en;q=0.9"},
		"Content-Type":    {"text/plain"},
		"Dnt":             {"1"},
		"Origin":          {service.Address},
		"Referer":         {service.Address + "/"},
		"User-Agent":      {"tplinkapi"},
	}
}

func (service RouterService) Logout() error {
	path := service.GetAPIURL("8")
	_, err := service.makeRequest(path, RequestLogout)
	if err != nil {
		return err
	}
	return nil
}

func (service RouterService) makeRequest(path string, body string) (string, error) {
	var (
		response string
		err      error
	)

	req, err := http.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if err != nil {
		return response, err
	}

	req.Header = service.GetHeaders()

	// req.AddCookie sanitizes the value rendering it unreadable by the server
	req.Header.Set("Cookie", fmt.Sprintf("Authorization=%s", service.GetAuthHeader()))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}
	res, err := client.Do(req)
	if err != nil {
		return response, err
	}

	defer res.Body.Close()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return response, err
	}

	bodyText := string(bodyBytes)
	if res.StatusCode != 200 {
		err = fmt.Errorf(res.Status)
		return bodyText, err
	}

	err = service.hasError(bodyText)
	return bodyText, err
}

func (service RouterService) hasError(body string) error {
	error := errorRegex.FindStringSubmatch(body)
	errorString := strings.TrimSpace(error[1])
	if errorString == "0" {
		return nil
	}
	return fmt.Errorf("error %s", errorString)
}

func (service RouterService) GetRouterInfo() (RouterInfo, error) {
	var (
		info RouterInfo
		err  error
	)
	path := service.GetAPIURL("1&1&1&8")
	body, err := service.makeRequest(path, RequestGetRouterInfo)
	if err != nil {
		return info, err
	}
	return ParseRouterInfo(body)
}

func (service RouterService) GetClientInfo() (Client, error) {
	var (
		client Client
		err    error
	)
	path := service.GetAPIURL("1&1&1&8")
	body, err := service.makeRequest(path, RequestGetRouterInfo)
	if err != nil {
		return client, err
	}
	return ParseClient(body)
}

func (service RouterService) GetLanConfig() (LanConfig, error) {
	var (
		cfg LanConfig
		err error
	)
	path := service.GetAPIURL("1&6&1")
	body, err := service.makeRequest(path, RequestLanConfig)
	if err != nil {
		return cfg, err
	}
	return ParseLanConfig(body)
}

func (service RouterService) GetStatistics() (ClientStatistics, error) {
	var (
		stats ClientStatistics
		err   error
	)
	path := service.GetAPIURL("1&5")
	body, err := service.makeRequest(path, RequestStatistics)
	if err != nil {
		return stats, err
	}
	return ParseStatistics(body)
}

func (service RouterService) GetAddressReservations() ([]ClientReservation, error) {
	reservations := make([]ClientReservation, 0)
	path := service.GetAPIURL("5")
	body, err := service.makeRequest(path, RequestAddressReservation)
	if err != nil {
		return reservations, err
	}
	return ParseReservations(body)
}

func (service RouterService) GetIpMacBindings() ([]ClientReservation, error) {
	reservations := make([]ClientReservation, 0)
	path := service.GetAPIURL("1&5")
	body, err := service.makeRequest(path, RequestIpMacBinding)
	if err != nil {
		return reservations, err
	}
	return ParseIpMacBinding(body)
}

func (service RouterService) makeDhcpReservation(client Client) error {
	body := fmt.Sprintf(RequestMakeDhcpReservation, client.Mac, client.IP)
	path := service.GetAPIURL("3")
	_, err := service.makeRequest(path, body)
	return err
}

func (service RouterService) makeIpMacBinding(client Client) error {
	body := fmt.Sprintf(RequestMakeIpMacBinding, client.IpAsInt(), client.Mac)
	path := service.GetAPIURL("3")
	_, err := service.makeRequest(path, body)
	return err
}

func (service RouterService) MakeIpAddressReservation(client Client) error {
	err := service.makeDhcpReservation(client)
	if err != nil {
		return err
	}
	return service.makeIpMacBinding(client)
}

func (service RouterService) deleteDhcpReservation(macAddress string) error {
	reservations, err := service.GetAddressReservations()
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
	_, err = service.makeRequest(path, body)
	return err
}

func (service RouterService) deleteIpMacBinding(macAddress string) error {
	reservations, err := service.GetIpMacBindings()
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
	_, err = service.makeRequest(path, body)
	return err
}

func (service RouterService) DeleteIpAddressReservation(macAddress string) error {
	err := service.deleteDhcpReservation(macAddress)
	if err != nil {
		return err
	}
	return service.deleteIpMacBinding(macAddress)
}

func (service RouterService) GetBandwidthControlDetails() (BandwidthControlDetail, error) {
	var config BandwidthControlDetail
	path := service.GetAPIURL("1&5&5")
	body, err := service.makeRequest(path, RequestBwControlInfo)
	if err != nil {
		return config, err
	}
	return ParseBandwidthControlInfo(body)
}

func (service RouterService) ToggleBandwidthControl(config BandwidthControlDetail) error {
	enable := 0
	if config.Enabled {
		enable = 3
	}
	body := fmt.Sprintf(RequestToggleBandwidthControl, enable, config.UpTotal, config.DownTotal)
	path := service.GetAPIURL("2")
	_, err := service.makeRequest(path, body)
	return err
}

func (service RouterService) GetBandwidthControlEntry(id int) (BandwidthControlEntry, error) {
	var entry BandwidthControlEntry
	body := fmt.Sprintf(RequestBandwidthControlEntry, id)
	path := service.GetAPIURL("1&1")
	body, err := service.makeRequest(path, body)
	if err != nil {
		return entry, err
	}
	return ParseBandwidthControlEntry(body)
}

func (service RouterService) AddBwControlEntry(entry BandwidthControlEntry) (int, error) {
	startIp, err := Ip2Int(entry.StartIp)
	if err != nil {
		return 0, err
	}
	endIp, err := Ip2Int(entry.EndIp)
	if err != nil {
		return 0, err
	}
	body := fmt.Sprintf(
		RequestAddBwControlEntry, startIp, endIp, entry.UpMin, entry.UpMax, entry.DownMin, entry.DownMax,
	)
	path := service.GetAPIURL("3")
	res, err := service.makeRequest(path, body)
	if err != nil {
		return 0, err
	}
	return GetId(res)
}

func (service RouterService) DeleteBwControlEntry(entryId int) error {
	details, err := service.GetBandwidthControlDetails()
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
	_, err = service.makeRequest(path, body)
	return err
}

func (service RouterService) ToggleInternetAccessControl(cfg InternetAccessControl) error {
	enable := 0
	filteringRule := 0
	if cfg.Enabled {
		enable = 1
		if cfg.DefaultDeny {
			filteringRule = 1
		}
	}

	body := fmt.Sprintf(RequestToggleInternetAccessControl, enable, filteringRule)
	path := service.GetAPIURL("2")
	_, err := service.makeRequest(path, body)
	return err
}

func (service RouterService) AddAccessControlHost(host AccessControlHostFormatter) (int, error) {
	var body string
	if h, ok := host.(IPRangeAccessControlHost); ok {
		startIP, err := Ip2Int(h.StartIP)
		if err != nil {
			return 0, err
		}

		endIP, err := Ip2Int(h.EndIP)
		if err != nil {
			return 0, err
		}

		body = fmt.Sprintf(
			"[INTERNAL_HOST#0,0,0,0,0,0#0,0,0,0,0,0]0,6\r\ntype=%d\r\nentryName=%s\r\nIPStart=%d\r\nIPEnd=%d\r\nportStart=%d\r\nportEnd=%d\r\n",
			h.Type, h.GetRef(), startIP, endIP, h.StartPort, h.EndPort,
		)
	} else if h, ok := host.(MacAddressAccessControlHost); ok {
		body = fmt.Sprintf(
			"[INTERNAL_HOST#0,0,0,0,0,0#0,0,0,0,0,0]0,3\r\ntype=%d\r\nentryName=%s\r\nmac=%s\r\n",
			h.Type, h.GetRef(), h.Mac,
		)
	} else {
		return 0, fmt.Errorf("")
	}

	path := service.GetAPIURL("3")
	body, err := service.makeRequest(path, body)
	if err != nil {
		return 0, err
	}
	return GetId(body)
}

func (service RouterService) RemoveAccessControlHost(id int) error {
	body := fmt.Sprintf(RequestDeleteAccessControlHost, id)
	path := service.GetAPIURL("4")
	_, err := service.makeRequest(path, body)
	return err
}

func (service RouterService) AddAccessControlRule(host AccessControlHostFormatter) (int, error) {
	body := fmt.Sprintf(RequestAddAccessControlRule, host.GetRef(), host.GetRef())
	path := service.GetAPIURL("3")
	body, err := service.makeRequest(path, body)
	if err != nil {
		return 0, err
	}
	return GetId(body)
}
