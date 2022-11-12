package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	Service RouterService = RouterService{
		Username: os.Getenv("USERNAME"),
		Password: os.Getenv("PASSWORD"),
		Address:  os.Getenv("ADDRESS"),
	}
)

func main() {
	routerInfo, err := GetRouterInfo(Service)
	if err != nil {
		exitWithError(err)
	}
	fmt.Printf("Info: %+v\n", routerInfo)

	// clientInfo, err := GetClientInfo(Service)
	// if err != nil {
	// 	exitWithError(err)
	// }
	// fmt.Printf("Info: %+v\n", clientInfo)

	// stats, err := GetStatistics(Service)
	// if err != nil {
	// 	exitWithError(err)
	// }
	// fmt.Printf("%d devices connected:\n", len(stats))
	// for _, client := range stats {
	// 	fmt.Printf("IP: %s Mac: %s Usage: %f\n", client.IP, client.Mac, client.BytesIn(MB))
	// }

	// reservations, err := GetAddressReservations(Service)
	// if err != nil {
	// 	exitWithError(err)
	// }
	// fmt.Printf("%d reservations made\n", len(reservations))
	// for _, r := range reservations {
	// 	fmt.Printf("Id: %d IP: %s Mac: %s Enabled: %v\n", r.Id, r.IP, r.Mac, r.Enabled)
	// }

	// reservations, err := GetIpMacBindings(Service)
	// if err != nil {
	// 	exitWithError(err)
	// }
	// fmt.Printf("%d reservations made\n", len(reservations))
	// for _, r := range reservations {
	// 	fmt.Printf("Id: %d IP: %s Mac: %s Enabled: %v\n", r.Id, r.IP, r.Mac, r.Enabled)
	// }

	// client := Client{
	// 	IP:  "192.168.0.186",
	// 	Mac: "F2:28:A9:A4:75:6C",
	// }
	// err := MakeIpAddressReservation(Service, client)
	// if err != nil {
	// 	exitWithError(err)
	// }

	// err := DeleteIpAddressReservation(Service, client.Mac)
	// if err != nil {
	// 	exitWithError(err)
	// }

	// bwControl, err := GetBandwidthControlDetails(Service)
	// if err != nil {
	// 	exitWithError(err)
	// }
	// fmt.Printf(
	// 	"Bandwidth control status: %v upTotal: %d downTotal: %d \nEntries: %d\n",
	// 	bwControl.Enabled, bwControl.UpTotal, bwControl.DownTotal, len(bwControl.Entries),
	// )
	// for _, entry := range bwControl.Entries {
	// 	fmt.Printf(
	// 		"IP: %s-%s MinUp: %d MaxUp: %d MinDown: %d MaxDown: %d Enabled: %v\n",
	// 		entry.StartIp, entry.EndIp, entry.UpMin, entry.UpMax, entry.DownMin, entry.DownMax, entry.Enabled,
	// 	)
	// }

	// config := BandwidthControlDetail{
	// 	Enabled:   true,
	// 	UpTotal:   80000,
	// 	DownTotal: 80000,
	// }
	// err := ToggleBandwidthControl(Service, config)
	// if err != nil {
	// 	exitWithError(err)
	// }

	// entry := BandwidthControlEntry{
	// 	Enabled: true,
	// 	StartIp: "192.168.0.251",
	// 	EndIp:   "192.168.0.254",
	// 	UpMin:   100,
	// 	UpMax:   150,
	// 	DownMin: 100,
	// 	DownMax: 150,
	// }
	// id, err := AddBwControlEntry(Service, entry)
	// if err != nil {
	// 	exitWithError(err)
	// }
	// fmt.Printf("Entry added with id %d\n", id)

	// err := DeleteBwControlEntry(Service, 15)
	// if err != nil {
	// 	exitWithError(err)
	// }

	// err = Service.Logout()
	// if err != nil {
	// 	exitWithError(err)
	// }
}

type RouterService struct {
	Username string
	Password string
	Address  string
}

func (router RouterService) GetAPIURL(params string) string {
	path := router.Address + "/cgi"
	if params != "" {
		path = path + "?" + params
	}
	return path
}

func (router RouterService) basicAuth(username, password string) string {
	auth := fmt.Sprintf("%s:%s", username, password)
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (router RouterService) GetAuthHeader() string {
	return "Basic " + router.basicAuth(router.Username, router.Password)
}

func (router RouterService) GetHeaders() http.Header {
	return http.Header{
		"Accept":          {"*/*"},
		"Accept-Language": {"en-US,en;q=0.9"},
		"Content-Type":    {"text/plain"},
		"Dnt":             {"1"},
		"Origin":          {router.Address},
		"Referer":         {router.Address + "/"},
		"User-Agent":      {"tplinkapi"},
	}
}

func (router RouterService) Logout() error {
	path := router.GetAPIURL("8")
	_, err := router.makeRequest(http.MethodPost, path, RequestLogout)
	if err != nil {
		return err
	}
	return nil
}

func (router RouterService) makeRequest(method string, path string, body string) (string, error) {
	var (
		response string
		err      error
	)

	req, err := http.NewRequest(method, path, strings.NewReader(body))
	if err != nil {
		return response, err
	}

	req.Header = router.GetHeaders()

	// req.AddCookie sanitizes the value rendering it unreadable by the server
	req.Header.Set("Cookie", fmt.Sprintf("Authorization=%s", router.GetAuthHeader()))

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

	err = HasError(bodyText)
	return bodyText, err
}

func exitWithError(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
