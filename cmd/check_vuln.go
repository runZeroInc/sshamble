package cmd

func initVulnChecks() {
	// Register pre-session vulnerability checks

	// Disabled by default due to false positives today
	registerCheck(checkVulnExecSkipUserAuth, "vuln", false, false)
	registerCheck(checkVulnExecSkipAuth, "vuln", false, false)

	// MikroTik SSH public-key auth bypass (CVE-2026-67276)
	registerCheck(checkVulnMikrotikPubkey, "vuln", false, true)

	// MikroTik WebFig unauthenticated file read (CVE-2026-67281) — not yet working
	// registerCheck(checkVulnMikrotikWebfigTraversal, "vuln", false, true)
}
