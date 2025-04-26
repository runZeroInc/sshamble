package cmd

func initVulnChecks() {
	// Register pre-session vulnerability checks
	registerCheck(checkVulnExecSkipUserAuth, "vuln", false, true)
	registerCheck(checkVulnExecSkipAuth, "vuln", false, true)
}
