package main

import (
	"fmt"
	"testing"
)

func TestIP(t *testing.T) {
	randIP, err := randomIPV6FromSubnet("2102:470::/35", "hello1")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(randIP)
}
