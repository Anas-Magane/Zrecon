package cmd

import (
	"fmt"
	"os"

	"github.com/Anas-Magane/zrecon/internal/banner"
	"github.com/Anas-Magane/zrecon/internal/logger"
	"github.com/Anas-Magane/zrecon/internal/metadata"
	"github.com/spf13/cobra"
)

var (
	flagSilent  bool
	flagNoColor bool
)

var rootCmd = &cobra.Command{
	Use:   "zrecon",
	Short: metadata.Description,
	Long:  metadata.Description,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if flagNoColor {
			logger.DisableColor()
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		banner.Print(flagSilent)
		return cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&flagSilent, "silent", false, "Display findings only")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "Disable colors")
	rootCmd.SetHelpTemplate(helpTemplate)
}

const helpTemplate = `Usage:
  {{.UseLine}}

{{if .HasAvailableSubCommands}}Commands:
  scan             Run a reconnaissance scan
  modules          Display available modules
  version          Display the current version
  help             Display the help menu
{{end}}
{{if .HasAvailableFlags}}Flags:
{{.LocalFlags.FlagUsages | trimRightSpace}}
{{end}}
Use "{{.CommandPath}} [command] --help" for more information about a command.
`
