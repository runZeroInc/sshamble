package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/logrusorgru/aurora/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sshamble {scan -o results.json 192.168.0.0/24, analyze results.json -d results-dir}",
	Short: "An exploration tool for (in)secure shell services",
	Long: `

▀██▄` + aurora.BrightCyan(`  ▀███████████████████████████████████████████████████████████████████████████████████████████`).String() + ` 
  ▀██▄                                                                                           
    ▀██▄     ▄████████  ▄████████  ██     ██` + aurora.BrightCyan(`  ▄███████▄  ▄████████▄  ████████▄  ██        ▄███████`).String() + `
      ▀██▄   ██         ██         ██     ██` + aurora.BrightCyan(`  ██     ██  ██  ██  ██  ██     ██  ██        ██      `).String() + `
        ███  ▀███████▄  ▀███████▄  █████████` + aurora.BrightCyan(`  █████████  ██  ██  ██  █████████  ██        ████████`).String() + `
      ▄██▀          ██         ██  ██     ██` + aurora.BrightCyan(`  ██     ██  ██  ██  ██  ██     ██  ██        ██      `).String() + `
    ▄██▀     ████████▀  ████████▀  ██     ██` + aurora.BrightCyan(`  ██     ██  ██  ██  ██  ████████▀   ▀██████  ▀███████`).String() + `
  ▄██▀                                                                                           
▄██▀` + aurora.BrightCyan(`  ▄███████████████████████████████████████████████████████████████████████████████████████████`).String() +
		`

An exploration tool for (in)secure shell services.


Start a network scan using:

$ sshamble scan -o results.json 192.168.0.0/24

Analyze the results using:

$ sshamble analyze results-directory results.json

`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	initBypassChecks()
	initPubkeyChecks()
	initPasswordChecks()
	initKeyboardChecks()
	initSessionChecks()
	initUserEnumChecks()
	initGSSAPIChecks()

	cobra.OnInitialize(initConfig)

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(analyzeCmd)

	rootCmd.CompletionOptions = cobra.CompletionOptions{DisableDefaultCmd: true}
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".sshamble" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("json")
		viper.SetConfigName(".sshamble")
	}

	viper.SetEnvPrefix("SSHAMBLE")

	viper.AutomaticEnv()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

var patTerminalEscapeSequences = regexp.MustCompile(`(\x9b|\x1b\[)[0-?]*[ -\/]*[@-~]`)

type TerminalModeHook struct {
	Writer    io.Writer
	LogLevels []logrus.Level
	Formatter logrus.Formatter
}

func (hook *TerminalModeHook) Fire(entry *logrus.Entry) error {
	line, err := hook.Formatter.Format(entry)
	if err != nil {
		return err
	}
	line = bytes.ReplaceAll(line, []byte{0x00}, []byte{})
	if gStdinManager != nil && gStdinManager.IsRawMode() {
		// Use CRLF for raw mode and don't filter escapes
		line = append([]byte{'\r', '\n'}, bytes.TrimSpace(line)...)
		line = append(line, '\r', '\n')
	} else {
		// Filter terminal escapes in non-interactive mode
		line = []byte(patTerminalEscapeSequences.ReplaceAll(line, []byte{}))
	}
	_, err = hook.Writer.Write(line)
	return err
}

func (hook *TerminalModeHook) Levels() []logrus.Level {
	return hook.LogLevels
}

type FileModeHook struct {
	Writer    io.Writer
	LogLevels []logrus.Level
	Formatter logrus.Formatter
}

func (hook *FileModeHook) Fire(entry *logrus.Entry) error {
	line, err := hook.Formatter.Format(entry)
	if err != nil {
		return err
	}
	line = bytes.ReplaceAll(line, []byte{0x00}, []byte{})

	// Filter terminal escapes
	line = []byte(patTerminalEscapeSequences.ReplaceAll(line, []byte{}))

	_, err = hook.Writer.Write(line)
	return err
}

func (hook *FileModeHook) Levels() []logrus.Level {
	return hook.LogLevels
}

func configureLogging(conf *ScanConfig) {
	allLevels := []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
		logrus.TraceLevel,
	}

	logger := logrus.New()
	logger.Out = os.Stderr
	logger.Formatter = &logrus.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
		ForceColors:     true,
	}

	switch strings.ToLower(gLogLevel) {
	case "trace":
		logger.Level = logrus.TraceLevel
	case "debug":
		logger.Level = logrus.DebugLevel
	case "info":
		logger.Level = logrus.InfoLevel
	case "warn":
		logger.Level = logrus.WarnLevel
	case "error":
		logger.Level = logrus.ErrorLevel
	}

	// Store the logger in the config
	conf.Logger = logger

	// Discard and use the hooks instead
	logger.Out = io.Discard

	// Configure the formatter
	textFormatter := &logrus.TextFormatter{
		TimestampFormat: "2006-01-02 15:04:05",
		FullTimestamp:   true,
	}

	if gLogfile != "" && gLogfile != "-" {
		// Log to file
		logFD, err := os.OpenFile(gLogfile, os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			logger.Fatalf("can't open log '%s': %v", gLogfile, err)
		}

		logger.AddHook(&FileModeHook{
			Writer:    logFD,
			LogLevels: allLevels,
			Formatter: textFormatter,
		})
	} else {
		// Log to stderr
		logger.AddHook(&TerminalModeHook{
			Writer:    os.Stderr,
			LogLevels: allLevels,
			Formatter: textFormatter,
		})
	}
}
