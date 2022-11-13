# tplinkapi

This library provides an (unofficial) interface for interacting with a Tp-Link Router. Tested with TL-WR840N and IPv4.

This is still work in progress.

# Example
```Go
package main

import (
	"fmt"
	"os"
)

func main() {
    Service RouterService = RouterService{
		Username: os.Getenv("USERNAME"),
		Password: os.Getenv("PASSWORD"),
		Address:  os.Getenv("ADDRESS"),
	}

	routerInfo, err := Service.GetRouterInfo()
	if err != nil {
		exitWithError(err)
	}
	fmt.Printf("Info: %+v\n", routerInfo)
}
```
