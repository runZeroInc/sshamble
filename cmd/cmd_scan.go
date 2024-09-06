package cmd

import (
	"bufio"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/runZeroInc/sshamble/auth"
	"github.com/runZeroInc/sshamble/badkeys"
	"github.com/runZeroInc/sshamble/crypto/ssh"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// scanCmd handles scanning
var scanCmd = &cobra.Command{
	Use:   "scan [-p 22] [-u root,admin] [-o scan.json] [-l scan.log] [--log-level trace] 192.168.0.0/24 ...",
	Short: "Enumerates a set of targets for SSH capabilities and exposures",
	Long:  "Enumerates a set of targets for SSH capabilities and exposures",
	Run:   runScan,
}

var (
	gUsers                      string
	gPorts                      string
	gInputTargets               string
	gMaxConnections             uint
	gTimeout                    uint
	gRetries                    uint
	gClientVersion              string
	gPubKeyBulkLimit            uint
	gPubKeyHuntFile             string
	gPubKeyHuntConnLimit        uint
	gEnabledCategories          string
	gEnabledChecks              string
	gPrivateKeyFile             string
	gPrivateKeyPassphrase       string
	gPassword                   string
	gPasswordFile               string
	gInteract                   string
	gInteractAuto               string
	gUserEnumTestCount          uint
	gUserEnumMaxPerSessionCount uint
	gOutput                     string
	gLogfile                    string
	gLogLevel                   string
	gPProfPort                  string

	interactMutex sync.Mutex
)

type sshCheck struct {
	Name          string
	Category      string
	Authenticated bool
	Enabled       bool
}

var Checks []sshCheck

func registerCheck(name string, category string, authenticated bool, enabled bool) {
	Checks = append(Checks, sshCheck{
		Name:          name,
		Category:      category,
		Authenticated: authenticated,
		Enabled:       enabled,
	})
}

func init() {
	categoryMap := make(map[string]struct{})
	checkMap := make(map[string]struct{})
	disabledCheckMap := make(map[string]struct{})
	for _, v := range Checks {
		if !v.Enabled {
			disabledCheckMap[v.Name] = struct{}{}
			categoryMap[v.Category] = struct{}{}
			continue
		}
		categoryMap[v.Category] = struct{}{}
		checkMap[v.Name] = struct{}{}
	}
	categories := []string{}
	for k := range categoryMap {
		categories = append(categories, k)
	}
	sort.Strings(categories)

	checks := []string{}
	for k := range checkMap {
		checks = append(checks, k)
	}
	sort.Strings(checks)

	disabledChecks := []string{}
	for k := range disabledCheckMap {
		disabledChecks = append(disabledChecks, k)
	}
	sort.Strings(disabledChecks)

	scanCmd.Flags().StringVarP(&gOutput, "output", "o", "stdout", "The destination file for JSON output")
	scanCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.sshamble.json)")
	scanCmd.Flags().StringVarP(&gUsers, "users", "u", "root", "The list of usernames to test on each target (comma-separated)")
	scanCmd.Flags().StringVarP(&gPorts, "ports", "p", "22", "The list of ports to check when not specified with the target (comma-separated)")
	scanCmd.Flags().StringVarP(&gInputTargets, "input-targets", "i", "", "The optional file to read targets from")
	scanCmd.Flags().StringVar(&gPubKeyHuntFile, "pubkey-hunt-file", "", "The optional file containing public keys to hunt")
	scanCmd.Flags().UintVar(&gPubKeyHuntConnLimit, "pubkey-hunt-conn-limit", 250000, "The number of public keys to test in each connection")
	scanCmd.Flags().StringVar(&gClientVersion, "client-version", "OpenSSH_9.8p1", "The client version string to send")
	scanCmd.Flags().UintVarP(&gMaxConnections, "max-connections", "m", 5000, "The maximum number of concurrent connections")
	scanCmd.Flags().UintVar(&gPubKeyBulkLimit, "pubkey-bulk-limit", 10, "The number of pubkey half-auths to test for max attempts")
	scanCmd.Flags().UintVar(&gTimeout, "timeout", 5, "The number of seconds to wait for a target to respond")
	scanCmd.Flags().StringVar(&gEnabledChecks, "checks", strings.Join(checks, ","), "The list of checks to run. Non-default (\""+strings.Join(disabledChecks, ",")+"\")")
	scanCmd.Flags().StringVar(&gEnabledCategories, "categories", strings.Join(categories, ","), "The list of categories to include.")
	scanCmd.Flags().StringVar(&gPrivateKeyFile, "private-key", "", "The optional file containing a private key for authentication")
	scanCmd.Flags().StringVar(&gPrivateKeyPassphrase, "private-key-passphrase", "", "The optional passphrase for a private key file")
	scanCmd.Flags().StringVar(&gPassword, "password", "", "An optional password to try for authentication")
	scanCmd.Flags().StringVar(&gPasswordFile, "password-file", "", "An optional file with clear-text passwords to try for authentication")
	scanCmd.Flags().StringVarP(&gInteract, "interact", "I", "none", "Open an interactive shell for the 'first', 'all', or 'none' sessions")
	scanCmd.Flags().StringVar(&gInteractAuto, "interact-auto", "pty,shell", "A comma-separated set of commands to run in the interactive session")
	scanCmd.Flags().UintVar(&gUserEnumTestCount, "userenum-test-count", 2500, "The number of tests to apply during username enumeration")
	scanCmd.Flags().UintVar(&gUserEnumMaxPerSessionCount, "userenum-max-per-session-count", 1023, "The maximum number of authentication atempts per session")
	scanCmd.Flags().StringVarP(&gLogfile, "log", "l", "-", "The file to write logs to (default is stderr)")
	scanCmd.Flags().StringVarP(&gLogLevel, "log-level", "L", "info", "The log level to write (trace,debug,info,warn,error)")
	scanCmd.Flags().StringVar(&gPProfPort, "pprof", "", "Start a Go pprof debug listener on the provided port")
	scanCmd.Flags().UintVar(&gRetries, "retries", 2, "The retry count for subsequent failed connections after an initial success")
}

var TestKeyRSASizes = []int{1024, 2048, 4096}

type ScanConfig struct {
	EnabledChecks  map[string]struct{}
	Logger         *logrus.Logger
	OutputWriter   io.Writer
	TestKeyRSA1024 ssh.Signer
	TestKeyRSA2048 ssh.Signer
	TestKeyRSA4096 ssh.Signer
	TestKeyED25519 ssh.Signer
	BadKeyCache    *badkeys.Cache
	outMutex       sync.Mutex
	statResult     atomic.Uint64
}

func (conf *ScanConfig) IsCheckEnabled(check string) bool {
	_, enabled := conf.EnabledChecks[check]
	return enabled
}

func runScan(cmd *cobra.Command, args []string) {
	var err error

	// Bump rlimit for file handles
	increaseFileLimit()

	// Start pprof
	startProfiler()

	conf := &ScanConfig{}

	// Configure logging
	configureLogging(conf)

	var statTargetsTotal atomic.Uint64
	var statTargetsDone atomic.Uint64

	// Configure output
	outputWriter := os.Stdout
	if gOutput != "" {
		switch gOutput {
		case "-", "stdout":
			// Default is stdout
		case "stderr":
			outputWriter = os.Stderr
		default:
			outputWriter, err = os.OpenFile(gOutput, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				conf.Logger.Fatalf("failed to create output file %s: %v", gOutput, err)
			}
		}
	}
	conf.OutputWriter = outputWriter

	if gUserEnumTestCount == 0 {
		conf.Logger.Fatalf("user enumeration test count must be more than 0")
	}

	if gPassword != "" && strings.Contains(gPassword, ",") {
		conf.Logger.Warnf("password field is singular, but contains a comma (%s), consider --password-file instead", gPassword)
	}

	bkc := badkeys.NewCache(conf.Logger)
	if _, err := bkc.LoadBlocklist(); err == nil {
		conf.BadKeyCache = bkc
	} else {
		conf.Logger.Infof("badkeys detection is not active, run `sshamble badkeys-update` to enable")
	}

	// Parse the port list
	scanPorts, err := parsePorts(gPorts)
	if err != nil {
		conf.Logger.Fatalf("invalid port '%s': %v", gPorts, err)
	}

	// Parse the check lists and categories
	enabledChecks := make(map[string]struct{})
	for _, v := range strings.Split(gEnabledChecks, ",") {
		v = strings.ToLower(strings.TrimSpace(v))
		enabledChecks[v] = struct{}{}
	}
	enabledCategories := make(map[string]struct{})
	for _, v := range strings.Split(gEnabledCategories, ",") {
		v = strings.ToLower(strings.TrimSpace(v))
		enabledCategories[v] = struct{}{}
	}
	allowedChecks := []string{}
	for _, v := range Checks {
		if _, ok := enabledCategories[v.Category]; !ok {
			continue
		}
		if _, ok := enabledChecks[v.Name]; !ok {
			continue
		}
		allowedChecks = append(allowedChecks, v.Name)
	}
	if len(allowedChecks) == 0 {
		conf.Logger.Fatalf("no checks are enabled")
	}
	conf.EnabledChecks = enabledChecks

	if (gInputTargets == "-" || gInputTargets == "stdin") && gInteract != "none" {
		conf.Logger.Fatalf("unable to read targets from stdin while interact is enabled")
	}

	// Configure private key
	var privateKey ssh.Signer
	if gPrivateKeyFile != "" {
		privateKey, err = processPrivateKeyFile(conf)
		if err != nil {
			conf.Logger.Fatalf("failed to load private key: %v", err)
		}
	}

	// Generate test keys
	generateTestKeys(conf)

	// Prepare for the job
	wg := sync.WaitGroup{}
	ch := make(chan *auth.Options, 1)

	// Process one concurrent task per connection
	for range gMaxConnections {
		wg.Add(1)
		go conf.ScanTarget(ch, &wg, &statTargetsDone)
	}

	// Write status messages
	stime := time.Now()
	writeStatus := func(final bool) {
		waitForInteract()
		done := statTargetsDone.Load()
		if final {
			conf.Logger.Infof("scan completed %d tasks in %ds", done, uint(time.Since(stime)/time.Second))
		} else if done > 0 {
			conf.Logger.Infof("scan processed %d tasks in %ds", done, uint(time.Since(stime)/time.Second))
		}
	}

	// Status writer close signal
	statusCh := make(chan int, 1)

	// Start status writer
	go func() {
		defer func() {
			if r := recover(); r != nil {
				conf.Logger.Errorf("panic: status writer %v", r)
			}
		}()
		t := time.NewTicker(time.Second * 5)
		for {
			select {
			case <-t.C:
				writeStatus(false)
			case <-statusCh:
				writeStatus(true)
				t.Stop()
				return
			}
		}
	}()

	inputCh := make(chan string, 1)
	inputWg := sync.WaitGroup{}
	inputWg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				conf.Logger.Errorf("panic: worker %v", r)
			}
			inputWg.Done()
		}()

		for line := range inputCh {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			users := gUsers
			user, host, hasUser := strings.Cut(line, "@")
			if hasUser {
				users = users + "," + user
				line = host
			}
			addr, portStr, err := net.SplitHostPort(line)
			if err != nil {
				addr = line
				portStr = ""
			}
			ports := scanPorts
			if portStr != "" {
				portInt, _ := strconv.Atoi(portStr)
				if !validPort(portInt) {
					conf.Logger.Fatalf("invalid port in target '%s'", line)
				}
				ports = []int{portInt}
			}
			for _, port := range ports {
				statTargetsTotal.Add(1)
				ch <- &auth.Options{
					Host:          addr,
					Port:          port,
					Usernames:     users,
					HostKeyAlgs:   auth.HostKeyAlgorithms,
					PrivateKey:    privateKey,
					Timeout:       time.Second * time.Duration(gTimeout),
					Logger:        conf.Logger,
					ClientVersion: gClientVersion,
					SessionPoke:   "\r\n\r\n",
				}
			}

		}
	}()

	// Process any input files as targets
	if gInputTargets != "" {
		var readFD io.Reader = os.Stdin
		if gInputTargets != "-" && gInputTargets != "stdin" {
			fd, err := os.Open(gInputTargets)
			if err != nil {
				conf.Logger.Fatalf("failed to read input target file '%s': %v", gInputTargets, err)
			}
			defer fd.Close()
			readFD = fd
		}

		scan := bufio.NewScanner(readFD)
		buff := make([]byte, auth.MaxTargetLine)
		scan.Buffer(buff, auth.MaxTargetLine)

		inputName := gInputTargets
		if inputName == "-" {
			inputName = "stdin"
		}
		conf.Logger.Infof("reading targets from %s...", inputName)
		for scan.Scan() {
			line := scan.Text()
			targets, err := parseTargets(line)
			if err != nil {
				conf.Logger.Fatalf("invalid target %s: %v", line, err)
			}
			for _, target := range targets {
				inputCh <- target
			}
		}
	}

	// Start the stdin manager if interaction was requested
	if gInteract != "none" && gInteract != "" {
		conf.Logger.Debugf("interaction enabled, starting stdin manager...")
		gStdinManager = NewStdinManager()
	}

	// Add on any command-line targets
	for _, input := range args {
		targets, err := parseTargets(input)
		if err != nil {
			conf.Logger.Fatalf("invalid target %s: %v", input, err)
		}
		for _, target := range targets {
			inputCh <- target
		}
	}

	// Close input channel
	close(inputCh)

	// Wait on input processing
	inputWg.Wait()

	// Close worker channel
	close(ch)

	// Wait on workers
	wg.Wait()

	// Stop the status reporter
	close(statusCh)
}

func (conf *ScanConfig) ScanTarget(ch chan *auth.Options, wg *sync.WaitGroup, statTargetsDone *atomic.Uint64) {
	defer wg.Done()
	for opt := range ch {
		waitForInteract()

		// Keep a per-addr:port cache to limit redundant checks
		var cached *auth.AuthResult

		// Iterate each username sequentially to limit concurrent port access
		for _, user := range uniqueUsers(opt.Usernames) {
			user = strings.TrimSpace(user)
			if user == "" {
				continue
			}
			r := conf.ScanHost(opt.WithUsername(user), cached)
			if cached == nil && r != nil {
				cached = r
			}
		}
		statTargetsDone.Add(1)
	}
}

func uniqueUsers(ustr string) []string {
	uniq := make(map[string]struct{}, 0)
	for _, user := range strings.Split(ustr, ",") {
		uniq[user] = struct{}{}
	}
	res := []string{}
	for user := range uniq {
		res = append(res, user)
	}
	return res
}

type sshCheckFunc func(string, *ScanConfig, *auth.Options, *auth.AuthResult) *auth.AuthResult

func (conf *ScanConfig) ScanHost(options *auth.Options, cached *auth.AuthResult) *auth.AuthResult {
	addr := net.JoinHostPort(options.Host, strconv.FormatUint(uint64(options.Port), 10))
	root := conf.GetSession(addr, options, cached)
	if root.Unreachable {
		conf.Logger.Debugf("%s is unreachable: %v", addr, root.Error)
		return nil
	}
	if root.SessionMethod != "" {
		conf.TestSession(addr, options, root)
	}
	conf.WriteOutput(root)
	if gInteract == "first" && root.SessionMethod != "" {
		if err := conf.StartInteract(addr, options, root); err != nil {
			conf.Logger.Errorf("%s failed to interact: %v", addr, err)
		}
	}
	return root
}

// GetSession runs through all potential checks that can lead to a session
func (conf *ScanConfig) GetSession(addr string, options *auth.Options, cached *auth.AuthResult) (root *auth.AuthResult) {
	// Start with a required "none" authentication check to determine server capabilities
	root = auth.SSHAuthNone(addr, options)

	// Exit early if we failed to get past the connection stage
	if root.Stage == "init" || root.Stage == "connect" {
		root.Unreachable = true
		return
	}
	options = options.WithRetries(gRetries)

	// Collect any additional host keys if needed
	conf.GetAllHostKeys(addr, options, root, cached)

	// Test for weak and compromised hostkeys
	hostkeyChecks := []sshCheckFunc{
		sshCheckBadKeysBlocklist,
	}
	for _, check := range hostkeyChecks {
		_ = check(addr, conf, options, root)
	}

	// Exit early if we obtained a session from 'none'
	if root.SessionMethod != "" {
		return
	}

	var res *auth.AuthResult

	shouldInteract := func() {
		if gInteract == "all" && res != nil && res.SessionMethod != "" {
			if err := conf.StartInteract(addr, options, root); err != nil {
				conf.Logger.Errorf("%s failed to interact: %v", addr, err)
			}
		}
	}

	shouldReturn := func() bool {
		if res != nil && res.Unreachable {
			conf.Logger.Errorf("%s failed to reconnect: %v", addr, res.Error)
			return true
		}
		if gInteract == "first" && root.SessionMethod != "" {
			conf.Logger.Warnf("%s returned a session, interacting via %s", addr, root.SessionMethod)
			return true
		}
		return false
	}

	// Test username-agnostic bypass conditions if not cached
	if cached == nil {
		// SkipUserAuthService
		res = sshCheckSkipUserAuthService(addr, conf, options, root)
		shouldInteract()
		if shouldReturn() {
			return
		}
	}

	// Test username-specific pre-authentication bypass mechanisms if no session was opened
	bypassChecks := []sshCheckFunc{
		sshCheckSkipAuth,
		sshCheckSkipAuthNone,
		sshCheckSkipAuthSuccess,
		sshCheckSkipAuthMethodEmpty,
		sshCheckSkipAuthMethodNull,
	}
	for _, check := range bypassChecks {
		res = check(addr, conf, options, root)
		shouldInteract()
		if shouldReturn() {
			return
		}
	}

	// The server accepts publickey auth, run specific checks in a specific order
	// These checks aren't helpful if we've already found a way to get session
	if root.SupportsAuth("publickey") {
		// Look for acceptance of any pub key
		res = sshCheckPubKeyAny(addr, conf, options, root)
		shouldInteract()
		if shouldReturn() {
			return
		}

		if root.PubKeyAnyHalfKey == nil {
			// Determine the half-auth limit
			res = sshCheckPubKeyBulkHalf(addr, conf, options, root)
			shouldInteract()
			if shouldReturn() {
				return
			}

			// Hunt for specific public keys
			if gPubKeyHuntFile != "" {
				// Half-auth test
				res = sshCheckPubKeyHunt(addr, conf, options, root)
				shouldInteract()
				if shouldReturn() {
					return
				}
			}
		}

		// Test pubkey-based checks that can lead to a session
		pubkeySessionChecks := []sshCheckFunc{
			sshCheckSkipAuthPubkeyAny,
			sshCheckUserKey,
		}
		for _, check := range pubkeySessionChecks {
			res = check(addr, conf, options, root)
			shouldInteract()
			if shouldReturn() {
				return
			}
		}
	}

	// The server accepts password authentication
	if root.SupportsAuth("password") {
		// Test pubkey-based checks that can lead to a session
		passwordSessionChecks := []sshCheckFunc{
			sshCheckPasswordAny,
			sshCheckPasswordEmpty,
			sshCheckPasswordNull,
			sshCheckPasswordUser,
			sshCheckPasswordChangeEmpty,
			sshCheckPasswordChangeNull,
		}
		for _, check := range passwordSessionChecks {
			res = check(addr, conf, options, root)
			shouldInteract()
			if shouldReturn() {
				return
			}
		}
	}

	// The server accepts keyboard-interactive authentication
	if root.SupportsAuth("keyboard-interactive") {
		// Test keyboard-interactive checks that can lead to a session
		keyboardSessionChecks := []sshCheckFunc{
			sshCheckKeyboardAny,
			sshCheckKeyboardEmpty,
			sshCheckKeyboardNull,
			sshCheckKeyboardUser,
		}
		for _, check := range keyboardSessionChecks {
			res = check(addr, conf, options, root)
			shouldInteract()
			if shouldReturn() {
				return
			}
		}
	}

	// The server accepts keyboard-interactive authentication
	if root.SupportsAuth("gssapi-with-mic") {
		// Test gssapi checks that can lead to a session
		gssSessionChecks := []sshCheckFunc{
			sshCheckGSSAPIAny,
		}
		for _, check := range gssSessionChecks {
			res = check(addr, conf, options, root)
			shouldInteract()
			if shouldReturn() {
				return
			}
		}
	}

	// Test user enumeration techniques
	userEnumChecks := []sshCheckFunc{
		sshCheckUserAuthNoneTiming,
		sshCheckUserAuthPasswordTiming,
		sshCheckUserAuthPubkeyTiming,
	}
	for _, check := range userEnumChecks {
		res = check(addr, conf, options, root)
		shouldInteract()
		if shouldReturn() {
			return
		}
	}

	return
}

var (
	patIsGo            = regexp.MustCompile(`^SSH-2.0-Go.*`)
	patIsRuckus        = regexp.MustCompile(`Please login:`)
	patIsLikelyOpenSSH = regexp.MustCompile(`^SSH-2\.0-OpenSSH`)
	patIsSoftServe     = regexp.MustCompile(`Soft Serve`)
)

// TestSession tries to gain further access through a SSH session
func (conf *ScanConfig) TestSession(addr string, options *auth.Options, root *auth.AuthResult) {
	// Checks that can lead to deeper access to this session
	sessionChecks := []sshCheckFunc{
		sshCheckVulnTCPForward,
		sshCheckVulnGenericEnv,
	}

	// Enable Go-based SSH service checks
	if patIsGo.MatchString(root.Version) {
		sessionChecks = append(sessionChecks, sshCheckVulnGogsEnv)
	}

	// Enable Ruckus SSH service checks
	if patIsRuckus.MatchString(root.SessionOutput) {
		sessionChecks = append(sessionChecks, sshCheckVulnRuckusPasswordEscape)
	}

	// Enable Soft Serve SSH service checks
	if patIsSoftServe.MatchString(root.SessionOutput) {
		sessionChecks = append(sessionChecks, sshCheckVulnSoftServe)
	}

	for _, check := range sessionChecks {
		res := check(addr, conf, options, root)
		if res == nil {
			continue
		}
		if res.Unreachable {
			conf.Logger.Errorf("%s skipping additional checks due to response %v", addr, res.Error)
			break
		}
	}
}

func (conf *ScanConfig) GetAllHostKeys(addr string, options *auth.Options, root *auth.AuthResult, cached *auth.AuthResult) {
	if cached != nil && len(cached.HostKeys) > 0 {
		// Use cached hostkeys if available
		for k, v := range cached.HostKeys {
			root.HostKeys[k] = v
		}
		return
	}

	// Collect additional host key types using none authentication
	if root.KexInit == nil {
		return
	}
	if len(root.KexInit.ServerHostKeyAlgos) == 0 {
		return
	}
	for name, kt := range auth.HostKeyTypeMap {
		haveHK := false
		supportedAlg := false
		for _, hka := range kt {
			if _, found := root.HostKeys[hka]; found {
				haveHK = true
				break
			}
			if root.SupportsHostKey(hka) {
				supportedAlg = true
				break
			}
		}
		if haveHK || !supportedAlg {
			continue
		}
		hkOnlyOpts := options.WithStopStage("kex").WithHostKeyAlgs(auth.HostKeyTypeMap[name])
		kres := auth.SSHAuthNone(addr, hkOnlyOpts)
		for kt, kval := range kres.HostKeys {
			if _, found := root.HostKeys[kt]; !found {
				root.HostKeys[kt] = kval
			}
		}
	}
}

func waitForInteract() {
	if gInteract == "none" {
		return
	}
	// Pause new targets when interacting with a session
	for {
		if !interactMutex.TryLock() {
			time.Sleep(time.Second / 4)
			continue
		}
		interactMutex.Unlock()
		break
	}
}
