package cmd

func initVulnChecks() {
	// Register pre-session vulnerability checks

	// Disabled by default due to false positives today
	registerCheck(checkVulnExecSkipUserAuth, "vuln", false, false)
	registerCheck(checkVulnExecSkipAuth, "vuln", false, false)

	// MikroTik SSH public-key auth bypass (CVE-2026-67276)
	registerCheck(checkVulnMikrotikPubkey, "vuln", false, true)

	// MikroTik SSH pre-auth rekey session (CVE-2026-67279)
	registerCheck(checkVulnMikrotikPreauthRekey, "vuln", false, true)

	// MikroTik SSH login-helper fd injection (CVE-2026-86060)
	registerCheck(checkVulnMikrotikFD2Inject, "vuln", false, true)

	// OpenSSH with musl and PAM disabled accepts any password for accounts
	// whose crypt(3) hash is "*"; only probed on releases before 10.6p2.
	registerCheck(checkVulnMuslCryptStar, "vuln", false, true)

	// MikroTik WebFig unauthenticated file read (CVE-2026-67281) — not yet working
	// registerCheck(checkVulnMikrotikWebfigTraversal, "vuln", false, true)
}
