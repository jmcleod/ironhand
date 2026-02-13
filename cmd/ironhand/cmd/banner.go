package cmd

import (
	"fmt"
)

const banner = `
  _____                 _    _                 _ 
 |_   _|               | |  | |               | |
   | |  _ __ ___  _ __ | |__| | __ _ _ __   __| |
   | | | '__/ _ \| '_ \|  __  |/ _` + "`" + ` | '_ \ / _` + "`" + ` |
  _| |_| | | (_) | | | | |  | | (_| | | | | (_| |
 |_____|_|  \___/|_| |_|_|  |_|\__,_|_| |_|\__,_|
                                                 
`

func printBanner() {
	fmt.Printf("\x1b[34m%s\x1b[0m", banner)
	fmt.Printf("\x1b[32m  Secure Encryption Service - Version %s\x1b[0m\n\n", Version)
}
