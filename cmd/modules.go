package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

type moduleInfo struct {
	Name     string
	Category string
	Mode     string
	Desc     string
}

var allModules = []moduleInfo{
	{"dns", "asset", "passive", "Enumerate DNS records"},
	{"subdomains", "asset", "passive", "Discover subdomains"},
	{"resolve", "asset", "active", "Resolve discovered assets"},
	{"reverse-dns", "asset", "passive", "Reverse DNS lookup"},
	{"ports", "network", "active", "Discover open TCP ports"},
	{"services", "network", "active", "Detect basic services"},
	{"http", "web", "active", "Probe HTTP and HTTPS"},
	{"technologies", "web", "active", "Detect web technologies"},
	{"headers", "web", "active", "Analyze security headers"},
	{"tls", "web", "active", "Collect TLS information"},
	{"report", "reporting", "local", "Generate reports"},
}

var modulesCmd = &cobra.Command{
	Use:   "modules",
	Short: "Display available modules",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%-16s %-14s %-10s %s\n", "NAME", "CATEGORY", "MODE", "DESCRIPTION")
		fmt.Printf("%-16s %-14s %-10s %s\n", "----", "--------", "----", "-----------")
		for _, m := range allModules {
			fmt.Printf("%-16s %-14s %-10s %s\n", m.Name, m.Category, m.Mode, m.Desc)
		}
	},
}

func init() {
	rootCmd.AddCommand(modulesCmd)
}
