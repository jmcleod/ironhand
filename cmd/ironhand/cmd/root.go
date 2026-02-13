package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "ironhand",
	Short: "IronHand is a secure encryption service",
	Long: `A Secure Encryption Service to manage secrets, passwords and other sensitive data.
Complete documentation is available at https://github.com/jmcleod/ironhand`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Define flags and configuration settings here.
}
