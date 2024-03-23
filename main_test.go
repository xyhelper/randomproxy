package main

import (
	"fmt"
	"testing"
)

func TestIP(t *testing.T) {
	randIP, err := randomIPV6FromSubnet("2102:470::/35", ":30002")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(randIP)

	// 2102:470:4939:af51:de7b:1295:2cd3:7817
	// 2102:470:4939:af51:de7b:1295:2cd3:7817
	// 2102:470:1439:3832:6161:6264:3561:3038
	// 2102:470:1439:3832:6161:6264:3561:3038
	// 2102:470:166:3531:6465:3762:3132:3935
}
