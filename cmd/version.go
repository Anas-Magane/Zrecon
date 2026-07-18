package cmd

import (
	"fmt"

	"github.com/Anas-Magane/zrecon/internal/metadata"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display the current version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s v%s\n", metadata.ToolName, metadata.Version)
		fmt.Printf("Author: %s\n", metadata.Author)
		fmt.Printf("GitHub: %s\n", metadata.GitHubURL)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
