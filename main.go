package main

import (
	"flag"
	"os"
)

func main() {
	args := GetArg()
	if args.Help {
		flag.Usage()
		os.Exit(0)
	}
}
