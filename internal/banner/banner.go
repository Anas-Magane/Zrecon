package banner

import (
	"fmt"

	"github.com/Anas-Magane/zrecon/internal/metadata"
	"github.com/fatih/color"
)

func Print(silent bool) {
	if silent {
		return
	}

	cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()

	logo := `
███████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
╚══███╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ███╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ███╔╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
███████╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝`

	fmt.Println(cyan(logo))
	fmt.Println()
	fmt.Printf("       %s\n", blue(metadata.Description))
	fmt.Println()
	fmt.Printf("       Author   : %s\n", blue(metadata.Author))
	fmt.Printf("       GitHub   : %s\n", blue(metadata.GitHubURL))
	fmt.Printf("       LinkedIn : %s\n", blue(metadata.LinkedInURL))
	fmt.Printf("       Version  : %s\n", blue("v"+metadata.Version))
	fmt.Println()
}
