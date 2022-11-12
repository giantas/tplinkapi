package main

import (
	"fmt"
	"os"
)

var (
	Service RouterService = RouterService{
		Username: os.Getenv("USERNAME"),
		Password: os.Getenv("PASSWORD"),
		Address:  os.Getenv("ADDRESS"),
	}
)

func main() {
	routerInfo, err := Service.GetRouterInfo()
	if err != nil {
		exitWithError(err)
	}
	fmt.Printf("Info: %+v\n", routerInfo)

	// clientInfo, err := Service.GetClientInfo()
	// if err != nil {
	// 	exitWithError(err)
	// }
	// fmt.Printf("Info: %+v\n", clientInfo)

	// stats, err := Service.GetStatistics()
	// if err != nil {
	// 	exitWithError(err)
	// }
	// fmt.Printf("%d devices connected:\n", len(stats))
	// for _, client := range stats {
	// 	fmt.Printf("IP: %s Mac: %s Usage: %f\n", client.IP, client.Mac, client.BytesIn(MB))
	// }

	// reservations, err := Service.GetAddressReservations()
	// if err != nil {
	// 	exitWithError(err)
	// }
	// fmt.Printf("%d reservations made\n", len(reservations))
	// for _, r := range reservations {
	// 	fmt.Printf("Id: %d IP: %s Mac: %s Enabled: %v\n", r.Id, r.IP, r.Mac, r.Enabled)
	// }

	// reservations, err := Service.GetIpMacBindings()
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
	// err := Service.MakeIpAddressReservation(client)
	// if err != nil {
	// 	exitWithError(err)
	// }

	// err := Service.DeleteIpAddressReservation(client.Mac)
	// if err != nil {
	// 	exitWithError(err)
	// }

	// bwControl, err := Service.GetBandwidthControlDetails()
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
	// err := Service.ToggleBandwidthControl(config)
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
	// id, err := Service.AddBwControlEntry(entry)
	// if err != nil {
	// 	exitWithError(err)
	// }
	// fmt.Printf("Entry added with id %d\n", id)

	// err := Service.DeleteBwControlEntry(15)
	// if err != nil {
	// 	exitWithError(err)
	// }

	// err = Service.Logout()
	// if err != nil {
	// 	exitWithError(err)
	// }
}

func exitWithError(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
