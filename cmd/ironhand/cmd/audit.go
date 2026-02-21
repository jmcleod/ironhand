package cmd

import "github.com/spf13/cobra"

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log verification tools",
	Long:  `Commands for verifying and inspecting exported vault audit logs.`,
}

func init() {
	rootCmd.AddCommand(auditCmd)
}
