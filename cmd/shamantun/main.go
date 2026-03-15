package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

var version = "dev"

/* Parses CLI flags and launches the application runtime. */
func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	var (
		cfgPath  string
		debug    bool
		tunName  string
		printVer bool
	)

	flag.StringVar(&cfgPath, "c", "./config.json", "path to config json")
	flag.BoolVar(&debug, "debug", false, "enable verbose per-flow debug logs")
	flag.StringVar(&tunName, "tun", "", "override tun name")
	flag.BoolVar(&printVer, "v", false, "print version")
	flag.Parse()

	if printVer {
		fmt.Println(version)
		return
	}

	a := NewApp(version)
	if err := a.Run(cfgPath, tunName, debug); err != nil {
		logf(LogLevelError, "[FATAL] %v", err)
		os.Exit(1)
	}
}
