package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Anas-Magane/zrecon/internal/banner"
	"github.com/Anas-Magane/zrecon/internal/config"
	"github.com/Anas-Magane/zrecon/internal/engine"
	"github.com/Anas-Magane/zrecon/internal/logger"
	"github.com/Anas-Magane/zrecon/internal/models"
	dnsMod "github.com/Anas-Magane/zrecon/internal/modules/asset/dns"
	"github.com/Anas-Magane/zrecon/internal/modules/asset/resolve"
	"github.com/Anas-Magane/zrecon/internal/modules/asset/reversedns"
	"github.com/Anas-Magane/zrecon/internal/modules/asset/subdomains"
	"github.com/Anas-Magane/zrecon/internal/modules/network/ports"
	"github.com/Anas-Magane/zrecon/internal/modules/network/services"
	"github.com/Anas-Magane/zrecon/internal/modules/web/headers"
	httpMod "github.com/Anas-Magane/zrecon/internal/modules/web/http"
	"github.com/Anas-Magane/zrecon/internal/modules/web/technologies"
	tlsMod "github.com/Anas-Magane/zrecon/internal/modules/web/tls"
	"github.com/Anas-Magane/zrecon/internal/output"
	"github.com/Anas-Magane/zrecon/internal/report"
	"github.com/Anas-Magane/zrecon/internal/validator"
	"github.com/spf13/cobra"
)

var (
	// Target flags
	flagDomain string
	flagURL    string
	flagIP     string
	flagList   string

	// Scan flags
	flagModules      string
	flagAll          bool
	flagPassive      bool
	flagActive       bool
	flagThreads      int
	flagPortsSpec    string
	flagTopPorts     int
	flagTimeout      int
	flagRateLimit    int
	flagAuthorized   bool
	flagAllowPrivate bool

	// Output flags
	flagOutputDir string
	flagFormat    string
	flagVerbose   bool
	flagDebug     bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a reconnaissance scan",
	Long: `Run a full or selective reconnaissance scan against a target.

Examples:
  zrecon scan -d example.com
  zrecon scan -d example.com --passive
  zrecon scan -d example.com --all --authorized
  zrecon scan -d example.com -m dns,subdomains,http
  zrecon scan -i 8.8.8.8 -m ports,services --authorized
  zrecon scan -d example.com --ports 80,443,8080 --authorized`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if flagNoColor {
			logger.DisableColor()
		}
		banner.Print(flagSilent)
	},
	RunE: runScan,
}

func init() {
	// Target
	scanCmd.Flags().StringVarP(&flagDomain, "domain", "d", "", "Set the target domain")
	scanCmd.Flags().StringVarP(&flagURL, "url", "u", "", "Set the target URL")
	scanCmd.Flags().StringVarP(&flagIP, "ip", "i", "", "Set the target public IP address")
	scanCmd.Flags().StringVarP(&flagList, "list", "l", "", "Load targets from a file")

	// Scan
	scanCmd.Flags().StringVarP(&flagModules, "modules", "m", "", "Comma-separated module list")
	scanCmd.Flags().BoolVarP(&flagAll, "all", "a", false, "Run all modules")
	scanCmd.Flags().BoolVarP(&flagPassive, "passive", "p", false, "Run passive modules only")
	scanCmd.Flags().BoolVarP(&flagActive, "active", "A", false, "Enable active reconnaissance")
	scanCmd.Flags().IntVarP(&flagThreads, "threads", "t", 20, "Number of concurrent workers")
	scanCmd.Flags().StringVar(&flagPortsSpec, "ports", "", "Custom ports or ranges (e.g. 22,80,443,8000-8100)")
	scanCmd.Flags().IntVar(&flagTopPorts, "top-ports", 100, "Scan top N common ports")
	scanCmd.Flags().IntVar(&flagTimeout, "timeout", 10, "Request timeout in seconds")
	scanCmd.Flags().IntVar(&flagRateLimit, "rate-limit", 50, "Maximum requests per second")
	scanCmd.Flags().BoolVar(&flagAuthorized, "authorized", false, "Confirm authorization to scan")
	scanCmd.Flags().BoolVar(&flagAllowPrivate, "allow-private", false, "Allow private IP addresses")

	// Output
	scanCmd.Flags().StringVarP(&flagOutputDir, "output", "o", "./results", "Output directory")
	scanCmd.Flags().StringVarP(&flagFormat, "format", "f", "", "Output format: txt, json, html (default: all)")
	scanCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false, "Verbose logs")
	scanCmd.Flags().BoolVar(&flagDebug, "debug", false, "Debug logs")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	// Load config
	cfg, err := config.Load()
	if err != nil {
		logger.Warn(fmt.Sprintf("Could not load config: %v — using defaults", err))
	}

	// Apply config defaults if flags not set
	if cfg != nil {
		if !cmd.Flags().Changed("threads") && cfg.General.Threads > 0 {
			flagThreads = cfg.General.Threads
		}
		if !cmd.Flags().Changed("rate-limit") && cfg.General.RateLimit > 0 {
			flagRateLimit = cfg.General.RateLimit
		}
		if !cmd.Flags().Changed("output") && cfg.Output.Directory != "" {
			flagOutputDir = cfg.Output.Directory
		}
	}

	// Initialize logger
	logW := io.Discard
	logger.Init(flagVerbose, flagDebug, flagSilent, logW)

	// Validate — exactly one target flag
	targetCount := 0
	if flagDomain != "" {
		targetCount++
	}
	if flagURL != "" {
		targetCount++
	}
	if flagIP != "" {
		targetCount++
	}
	if flagList != "" {
		targetCount++
	}

	if targetCount == 0 {
		return fmt.Errorf("a target is required: use -d, -u, -i, or -l")
	}
	if targetCount > 1 {
		return fmt.Errorf("only one target option may be used at a time")
	}

	// Validate and parse target(s)
	var targets []*models.Target
	if flagList != "" {
		ts, errs := validator.LoadTargetFile(flagList, flagAllowPrivate)
		for _, e := range errs {
			logger.Warn(fmt.Sprintf("Target skipped: %v", e))
		}
		if len(ts) == 0 {
			return fmt.Errorf("no valid targets found in %s", flagList)
		}
		targets = ts
	} else {
		var t *models.Target
		var verr error
		switch {
		case flagDomain != "":
			t, verr = validator.ValidateDomain(flagDomain, flagAllowPrivate)
		case flagURL != "":
			t, verr = validator.ValidateURL(flagURL, flagAllowPrivate)
		case flagIP != "":
			t, verr = validator.ValidateIP(flagIP, flagAllowPrivate)
		}
		if verr != nil {
			return fmt.Errorf("invalid target: %w", verr)
		}
		targets = append(targets, t)
	}

	// Determine modules to run
	moduleSet := buildModuleSet()

	// Authorization check for active modules
	activeModules := []string{"resolve", "ports", "services", "http", "technologies", "headers", "tls"}
	requestingActive := false
	for _, m := range activeModules {
		if moduleSet[m] {
			requestingActive = true
			break
		}
	}

	if requestingActive && !flagAuthorized && !flagPassive {
		fmt.Println("[!] Active reconnaissance requires explicit authorization.")
		fmt.Println("[!] Use --authorized only when you own the target or have permission to test it.")
		fmt.Println("[!] Add --authorized to proceed, or use --passive for passive modules only.")
		return nil
	}

	// Scan each target
	for _, target := range targets {
		if err := scanTarget(target, moduleSet); err != nil {
			logger.Error(fmt.Sprintf("Scan failed for %s: %v", target.Raw, err))
		}
	}
	return nil
}

func buildModuleSet() map[string]bool {
	set := map[string]bool{}

	// Default passive set
	defaultPassive := []string{"dns", "subdomains", "reverse-dns"}
	// Default active set
	defaultActive := []string{"dns", "subdomains", "resolve", "reverse-dns", "http", "technologies", "headers", "tls"}

	if flagModules != "" {
		for _, m := range strings.Split(flagModules, ",") {
			set[strings.TrimSpace(m)] = true
		}
		return set
	}

	if flagPassive {
		for _, m := range defaultPassive {
			set[m] = true
		}
		return set
	}

	if flagAll || flagActive {
		all := []string{"dns", "subdomains", "resolve", "reverse-dns", "ports", "services", "http", "technologies", "headers", "tls"}
		for _, m := range all {
			set[m] = true
		}
		return set
	}

	// Default: passive + web (no ports by default without --authorized)
	for _, m := range defaultActive {
		set[m] = true
	}
	return set
}

func scanTarget(target *models.Target, moduleSet map[string]bool) error {
	logger.Info(fmt.Sprintf("Target validated: %s (%s)", target.Raw, target.Type))

	// Prepare output directory
	outDir, err := output.PrepareOutputDir(flagOutputDir, target.Raw)
	if err != nil {
		return fmt.Errorf("output dir: %w", err)
	}

	// Setup log file
	logFile, err := os.Create(filepath.Join(outDir, "scan.log"))
	if err != nil {
		logFile = os.Stderr
	}
	defer logFile.Close()
	logger.Init(flagVerbose, flagDebug, flagSilent, logFile)

	// Structured slog to file
	_ = slog.New(slog.NewTextHandler(logFile, nil))

	// Build scan config
	scanCfg := &models.ScanConfig{
		Passive:      flagPassive,
		Active:       flagActive || flagAll,
		Authorized:   flagAuthorized,
		Threads:      flagThreads,
		Ports:        flagPortsSpec,
		TopPorts:     flagTopPorts,
		Timeout:      flagTimeout,
		RateLimit:    flagRateLimit,
		OutputDir:    outDir,
		Verbose:      flagVerbose,
		Debug:        flagDebug,
		Silent:       flagSilent,
		AllowPrivate: flagAllowPrivate,
	}

	// Build engine
	eng := engine.New(scanCfg)

	// Register modules based on selection
	if moduleSet["dns"] {
		eng.Register(dnsMod.New())
	}
	if moduleSet["subdomains"] {
		eng.Register(subdomains.New(flagTimeout))
	}
	if moduleSet["resolve"] {
		eng.Register(resolve.New(flagThreads))
	}
	if moduleSet["reverse-dns"] {
		eng.Register(reversedns.New())
	}
	if moduleSet["ports"] {
		eng.Register(ports.New(flagThreads, flagTimeout, flagTopPorts, flagRateLimit, flagPortsSpec))
	}
	if moduleSet["services"] {
		eng.Register(services.New(flagTimeout))
	}
	if moduleSet["http"] {
		eng.Register(httpMod.New(flagThreads, flagTimeout))
	}
	if moduleSet["technologies"] {
		eng.Register(technologies.New(flagTimeout))
	}
	if moduleSet["headers"] {
		eng.Register(headers.New(flagTimeout))
	}
	if moduleSet["tls"] {
		eng.Register(tlsMod.New(flagTimeout))
	}

	// Setup context with Ctrl+C support
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Warn("Interrupt received — saving results...")
		cancel()
	}()

	// Run scan
	state, err := eng.Run(ctx, *target)
	if err != nil {
		return err
	}

	state.Result.CompletedAt = time.Now()

	// Generate reports
	formats := resolveFormats(flagFormat)
	writeReports(state, outDir, formats, state.Warnings)

	// Print summary
	if !flagSilent {
		output.PrintSummary(state.Result, outDir, state.Warnings)
	}

	return nil
}

func resolveFormats(f string) []string {
	if f == "" {
		return []string{"txt", "json", "html"}
	}
	var fmts []string
	for _, part := range strings.Split(f, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "txt" || part == "json" || part == "html" {
			fmts = append(fmts, part)
		}
	}
	if len(fmts) == 0 {
		return []string{"txt", "json", "html"}
	}
	return fmts
}

func writeReports(state *engine.ScanState, outDir string, formats []string, warnings []string) {
	for _, fmt := range formats {
		switch fmt {
		case "txt":
			if err := output.WriteTXT(outDir, state.Result, warnings); err != nil {
				logger.Error("Failed to write TXT report: " + err.Error())
			}
		case "json":
			if err := output.WriteJSON(outDir, state.Result); err != nil {
				logger.Error("Failed to write JSON report: " + err.Error())
			}
		case "html":
			if err := report.WriteHTML(outDir, state.Result); err != nil {
				logger.Error("Failed to write HTML report: " + err.Error())
			}
		}
	}
	logger.Info(fmt.Sprintf("Reports saved to: %s", outDir))
}
