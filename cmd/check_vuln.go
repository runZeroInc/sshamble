package cmd

func initVulnChecks() {
	// Register pre-session vulnerability checks

	// Disabled by default due to false positives today
	registerCheck(checkVulnExecSkipUserAuth, "vuln", false, false)
	registerCheck(checkVulnExecSkipAuth, "vuln", false, false)
}
