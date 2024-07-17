package main

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

func main() {
	var ok bool
	mapstructure.Decode("true", &ok)
	fmt.Println(ok)
}
