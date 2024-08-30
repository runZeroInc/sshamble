package cmd

import (
	"github.com/runZeroInc/sshamble/badkeys"
	"github.com/spf13/cobra"
)

// badkeysCmd processes a scan output file and buckets results
var badkeysCmd = &cobra.Command{
	Use:   "badkeys-update",
	Short: "Updates the badkeys.info blocklist cache.",
	Long:  "Updates the badkeys.info blocklist cache.",
	Run:   runBadKeys,
}

func init() {
	badkeysCmd.Flags().StringVarP(&gLogfile, "log", "l", "-", "The file to write logs to (default is stderr)")
	badkeysCmd.Flags().StringVarP(&gLogLevel, "log-level", "L", "debug", "The log level to write (trace,debug,info,warn,error)")
}

func runBadKeys(cmd *cobra.Command, args []string) {
	conf := &ScanConfig{}
	configureLogging(conf)

	bkc := badkeys.NewCache(conf.Logger)

	conf.Logger.Infof("updating badkeys cache from %s", badkeys.BadKeysMetaURL)
	over, nver, err := bkc.Update()
	if err != nil {
		conf.Logger.Fatalf("failed to update cache: %v", err)
	}
	conf.Logger.Infof("cache updated (old:%s, new:%s)", over, nver)
}
