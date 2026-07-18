package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/fatih/color"
)

var (
	infoPrefix    = color.New(color.FgCyan).Sprint("[*]")
	findingPrefix = color.New(color.FgGreen).Sprint("[+]")
	warnPrefix    = color.New(color.FgYellow).Sprint("[!]")
	errorPrefix   = color.New(color.FgRed).Sprint("[-]")
	startPrefix   = color.New(color.FgBlue).Sprint("[>]")
	donePrefix    = color.New(color.FgGreen, color.Bold).Sprint("[✓]")

	verbose bool
	debug   bool
	silent  bool

	Logger *slog.Logger
	logW   io.Writer
)

func Init(v, d, s bool, logFile io.Writer) {
	verbose = v
	debug = d
	silent = s
	logW = logFile

	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	Logger = slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: level}))
}

func Info(msg string) {
	if silent {
		return
	}
	fmt.Printf("%s %s\n", infoPrefix, msg)
	if Logger != nil {
		Logger.Info(msg)
	}
}

func Finding(msg string) {
	fmt.Printf("%s %s\n", findingPrefix, msg)
	if Logger != nil {
		Logger.Info("FINDING: " + msg)
	}
}

func Warn(msg string) {
	if !silent {
		fmt.Printf("%s %s\n", warnPrefix, msg)
	}
	if Logger != nil {
		Logger.Warn(msg)
	}
}

func Error(msg string) {
	if !silent {
		fmt.Fprintf(os.Stderr, "%s %s\n", errorPrefix, msg)
	}
	if Logger != nil {
		Logger.Error(msg)
	}
}

func ModuleStart(name string) {
	if !silent {
		fmt.Printf("%s Running %s\n", startPrefix, name)
	}
	if Logger != nil {
		Logger.Info("module started: " + name)
	}
}

func ModuleDone(name, detail string) {
	if !silent {
		if detail != "" {
			fmt.Printf("%s %s: %s\n", donePrefix, name, detail)
		} else {
			fmt.Printf("%s %s\n", donePrefix, name)
		}
	}
	if Logger != nil {
		Logger.Info("module completed: " + name)
	}
}

func Verbose(msg string) {
	if !verbose && !debug {
		return
	}
	if Logger != nil {
		Logger.Info("VERBOSE: " + msg)
	}
	if !silent {
		gray := color.New(color.FgHiBlack).Sprint
		fmt.Printf("%s %s\n", gray("[v]"), msg)
	}
}

func Debug(msg string) {
	if !debug {
		return
	}
	if Logger != nil {
		Logger.Debug(msg)
	}
	if !silent {
		gray := color.New(color.FgHiBlack).Sprint
		fmt.Printf("%s %s\n", gray("[d]"), msg)
	}
}

func DisableColor() {
	color.NoColor = true
	infoPrefix = "[*]"
	findingPrefix = "[+]"
	warnPrefix = "[!]"
	errorPrefix = "[-]"
	startPrefix = "[>]"
	donePrefix = "[✓]"
}
