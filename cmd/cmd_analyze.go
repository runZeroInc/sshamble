package cmd

import (
	"bufio"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
	"github.com/runZeroInc/sshamble/badkeys"
	"github.com/spf13/cobra"
)

// analyzeCmd processes a scan output file and buckets results
var analyzeCmd = &cobra.Command{
	Use:   "analyze -o results-directory scan.json ...",
	Short: "Analyzes a scan JSON output file and buckets results",
	Long:  "Analyzes a scan JSON output file and buckets results",
	Run:   runAnalyze,
}

const MaxJSONLine = 1024 * 1024 * 16

func init() {
	analyzeCmd.Flags().StringVarP(&gOutput, "output", "o", "", "The directory to place analysis results")
	analyzeCmd.Flags().StringVarP(&gLogfile, "log", "l", "-", "The file to write logs to (default is stderr)")
	analyzeCmd.Flags().StringVarP(&gLogLevel, "log-level", "L", "debug", "The log level to write (trace,debug,info,warn,error)")
}

func runAnalyze(cmd *cobra.Command, args []string) {
	conf := &ScanConfig{}
	configureLogging(conf)

	if gOutput == "" || gOutput == "-" || gOutput == "stdout" {
		conf.Logger.Fatalf("no output directory supplied (-o)")
	}

	if len(args) < 1 {
		conf.Logger.Fatalf("no input files specified")
	}

	if err := os.MkdirAll(gOutput, 0o755); err != nil {
		conf.Logger.Fatalf("failed to create output directory '%s': %v", gOutput, err)
	}

	bkc := badkeys.NewCache(conf.Logger)
	if _, err := bkc.LoadBlocklist(); err == nil {
		conf.BadKeyCache = bkc
	} else {
		conf.Logger.Infof("badkeys detection is not active, run `sshamble badkeys-update` to enable")
	}

	if err := os.MkdirAll(gOutput, 0o755); err != nil {
		conf.Logger.Fatalf("failed to create output directory '%s': %v", gOutput, err)
	}

	stats := NewAnalysisStats()

	for _, inp := range args {
		var readFD io.Reader = os.Stdin
		if inp != "-" && inp != "stdin" {
			fd, err := os.Open(inp)
			if err != nil {
				conf.Logger.Fatalf("failed to read input file %s: %v", inp, err)
			}
			defer fd.Close()
			readFD = fd
		}
		scan := bufio.NewScanner(readFD)
		buff := make([]byte, MaxJSONLine)
		scan.Buffer(buff, MaxJSONLine)

		conf.Logger.Infof("analyzing results from %s...", inp)
		cnt := 0
		for scan.Scan() {
			line := strings.TrimSpace(scan.Text())
			ores := auth.AuthResult{}
			if err := json.Unmarshal([]byte(line), &ores); err != nil {
				conf.Logger.Errorf("%s: failed to parse line: %s (%v)", inp, line, err)
			}
			if err := conf.AnalyzeResult(&ores, stats); err != nil {
				conf.Logger.Errorf("%s: failed to process line: %s (%v)", inp, line, err)
			}
			cnt++
			if cnt%100000 == 0 {
				conf.Logger.Debugf("processed %d results", cnt)
			}
		}
	}

	conf.writeAnalysisStats(stats, "stats_pubkey_limit", stats.PubKeyHalfAuthLimit)
	conf.writeAnalysisStats(stats, "stats_initial_stage", stats.InitialStage)
	conf.writeAnalysisStats(stats, "stats_hostkey_algos", stats.HostKeyAlgos)
	conf.writeAnalysisStats(stats, "stats_kex_algos", stats.KexAlgos)
	conf.writeAnalysisStats(stats, "stats_ciphers", stats.Ciphers)
	conf.writeAnalysisStats(stats, "stats_macs", stats.MACs)
	conf.writeAnalysisStats(stats, "stats_versions", stats.Versions)
	conf.writeAnalysisStats(stats, "stats_compression", stats.Compressions)
	conf.writeAnalysisStats(stats, "stats_auth_methods", stats.AuthMethods)
	conf.writeAnalysisStats(stats, "stats_session_methods", stats.SessionMethods)
	conf.writeAnalysisStats(stats, "stats_session_outputs", stats.SessionOutputs)
	conf.writeAnalysisStats(stats, "stats_hostkeys", stats.HostKeys)
}

type AnalysisStats struct {
	PubKeyHalfAuthLimit map[string]map[uint64]struct{}
	InitialStage        map[string]map[uint64]struct{}
	HostKeyAlgos        map[string]map[uint64]struct{}
	KexAlgos            map[string]map[uint64]struct{}
	Versions            map[string]map[uint64]struct{}
	Ciphers             map[string]map[uint64]struct{}
	MACs                map[string]map[uint64]struct{}
	Compressions        map[string]map[uint64]struct{}
	AuthMethods         map[string]map[uint64]struct{}
	SessionMethods      map[string]map[uint64]struct{}
	SessionOutputs      map[string]map[uint64]struct{}
	HostKeys            map[string]map[uint64]struct{}
	KeyMap              map[string]uint64
	KeyMapRev           map[uint64]*string
	keyCnt              uint64
}

func NewAnalysisStats() *AnalysisStats {
	return &AnalysisStats{
		InitialStage:        map[string]map[uint64]struct{}{},
		PubKeyHalfAuthLimit: map[string]map[uint64]struct{}{},
		HostKeyAlgos:        map[string]map[uint64]struct{}{},
		KexAlgos:            map[string]map[uint64]struct{}{},
		Versions:            map[string]map[uint64]struct{}{},
		Ciphers:             map[string]map[uint64]struct{}{},
		MACs:                map[string]map[uint64]struct{}{},
		Compressions:        map[string]map[uint64]struct{}{},
		AuthMethods:         map[string]map[uint64]struct{}{},
		SessionMethods:      map[string]map[uint64]struct{}{},
		SessionOutputs:      map[string]map[uint64]struct{}{},
		HostKeys:            map[string]map[uint64]struct{}{},
		KeyMap:              map[string]uint64{},
		KeyMapRev:           map[uint64]*string{},
	}
}

func addToMap(a *AnalysisStats, m map[string]map[uint64]struct{}, k1 string, k2 string) {
	v1, ok := m[k1]
	if !ok {
		m[k1] = make(map[uint64]struct{})
		v1 = m[k1]
	}
	lk, ok := a.KeyMap[k2]
	if !ok {
		nk := a.keyCnt
		a.keyCnt++
		a.KeyMap[k2] = nk
		a.KeyMapRev[nk] = &k2
		lk = nk
	}
	if _, ok := v1[lk]; !ok {
		m[k1][lk] = struct{}{}
	}
}

func (conf *ScanConfig) AnalyzeResult(res *auth.AuthResult, stats *AnalysisStats) error {
	addToMap(stats, stats.InitialStage, res.Stage, res.Host)
	if res.Stage == "init" || res.Stage == "connect" {
		return nil
	}

	if isHoneypot(conf, res) {
		conf.writeAnalysisRecord("honeypots", res)
	}

	if conf.BadKeyCache != nil && isBadKey(conf, res) {
		conf.writeAnalysisRecord("badkeys", res)
	}

	if name := isKnownDevice(conf, res); name != "" {
		conf.writeAnalysisRecord("session_known_"+name, res)
	} else if res.SessionMethod != "" {
		conf.writeAnalysisRecord("session_unknown", res)
	}

	if res.PubKeyHalfAuthLimit != 0 {
		addToMap(stats, stats.PubKeyHalfAuthLimit, strconv.Itoa(res.PubKeyHalfAuthLimit), res.Host)
	}

	addToMap(stats, stats.Versions, res.Version, res.Host)

	for _, v := range res.KexInit.ServerHostKeyAlgos {
		addToMap(stats, stats.HostKeyAlgos, v, res.Host)
	}
	for _, v := range res.KexInit.KexAlgos {
		addToMap(stats, stats.KexAlgos, v, res.Host)
	}
	for _, v := range res.KexInit.CiphersServerClient {
		addToMap(stats, stats.Ciphers, v, res.Host)
	}
	for _, v := range res.KexInit.MACsServerClient {
		addToMap(stats, stats.MACs, v, res.Host)
	}
	for _, v := range res.KexInit.CompressionServerClient {
		addToMap(stats, stats.Compressions, v, res.Host)
	}
	for _, v := range res.Methods {
		addToMap(stats, stats.AuthMethods, v, res.Host)
	}
	if res.SessionMethod != "" {
		addToMap(stats, stats.SessionMethods, res.SessionMethod, res.Host)
		conf.writeAnalysisRecord("session-"+res.SessionMethod, res)
		addToMap(stats, stats.SessionOutputs, res.SessionOutput, res.Host)
	}

	for kt, v := range res.HostKeys {
		addToMap(stats, stats.HostKeys, kt+" "+v, res.Host)
	}
	return nil
}

func (conf *ScanConfig) writeAnalysisRecord(name string, res *auth.AuthResult) {
	fd, err := os.OpenFile(filepath.Join(gOutput, filepath.Base(name)+".json"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		conf.Logger.Fatalf("failed to write file %s: %v", name, err)
	}
	defer fd.Close()
	rawb, _ := json.Marshal(res)
	rawb = append(rawb, '\n')
	_, _ = fd.Write(rawb)
}

func (conf *ScanConfig) writeAnalysisStats(stats *AnalysisStats, name string, vals map[string]map[uint64]struct{}) {
	fd, err := os.OpenFile(filepath.Join(gOutput, filepath.Base(name)+".csv"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		conf.Logger.Fatalf("failed to write file %s: %v", name, err)
	}
	wri := csv.NewWriter(fd)

	skeys := []string{}
	for k := range vals {
		skeys = append(skeys, k)
	}
	sort.SliceStable(skeys, func(i, j int) bool { return len(vals[skeys[i]]) > len(vals[skeys[j]]) })
	for _, k := range skeys {
		kclean := strings.Replace(k, ",", "_", -1)
		kclean = strings.Replace(kclean, "\"", "_", -1)
		hosts := []string{}
		for hostLK := range vals[k] {
			host, ok := stats.KeyMapRev[hostLK]
			if !ok {
				continue
			}
			hosts = append(hosts, *host)
		}
		sort.Strings(hosts)
		if err := wri.Write([]string{kclean, strconv.FormatInt(int64(len(vals[k])), 10), strings.Join(hosts, " ")}); err != nil {
			conf.Logger.Fatalf("failed to write row for %s: %v", name, err)
		}
	}
	wri.Flush()
	if err := wri.Error(); err != nil {
		conf.Logger.Fatalf("failed to flush data for %s: %v", name, err)
	}
	fd.Close()
}

var commonHoneypotStrings = []string{
	"The programs included with the Debian GNU/Linux system are free software;",
	"Welcome to Ubuntu",
}

func isHoneypot(conf *ScanConfig, res *auth.AuthResult) bool {
	for _, t := range commonHoneypotStrings {
		if strings.Contains(res.SessionOutput, t) {
			return true
		}
	}
	return false
}

func isBadKey(conf *ScanConfig, res *auth.AuthResult) bool {
	found := 0
	for hkt, hkv := range res.HostKeys {
		raw, err := base64.StdEncoding.DecodeString(hkv)
		if err != nil {
			continue
		}
		pk, err := ssh.ParsePublicKey(raw)
		if err != nil {
			continue
		}
		hpre, err := badkeys.PrefixFromPublicKey(pk)
		if err != nil {
			continue
		}
		bkr, err := conf.BadKeyCache.Blocklist.LookupPrefix(hpre)
		if err != nil {
			continue
		}
		res.AddVuln(auth.VulnResult{
			ID:    "badkeys-" + bkr.RepoType + "-" + bkr.Repo + "-" + bkr.RepoPath + "-" + hkt,
			Ref:   "https://badkeys.info/",
			Proof: bkr.ToURL(),
		})
		found++
	}
	return found != 0
}

var commonDeviceStrings = map[string]string{
	"sonicwall":    "SonicWall",
	"atos":         "ATOSNT Remote CLI", // No password
	"yamaha-rtx":   "Error: Login access is restricted",
	"dlink":        "D-Link Corporation",
	"ssaudit":      "Input target server",
	"digi":         "Welcome. Your access level is", // Authentication bypass
	"tandberg":     "Cisco Codec Release",
	"hpilo":        "hpiLO->", // Security override switch enabled
	"huawei-home":  "Welcome Visiting Huawei Home Gateway",
	"vstfs1":       "Team Foundation Server",
	"iboot":        "Boot-PDU",
	"lancom":       "Connection No.:",
	"realpresence": "Here is what I know about myself",
	"mikrotik":     "MikroTik RouterOS",
	"exceed":       "exceeds the specificaitons",
	"hpswitch":     "HEWLETT-PACKARD COMPANY, 3000 Hanover St",
	"gitee":        "GITEE.COM does not provide shell access",
	"tl1":          "Starting Interactive TL1",
	"sshs":         "SSHS>",
	"keenetic":     "https://keenetic",
	"vstfs2":       "Your Git command did not succeed",
	"cellrtr":      "Cellular Router>",
	"ruckus":       "Please login: \r\nPlease login",
	"snips.sh":     "snips.sh",
	"mioffice_mfa": "https://xiaomi.f.mioffice.cn",
	"l2switch":     "Welcome to Layer 2 Managed Switch",
}

func isKnownDevice(conf *ScanConfig, res *auth.AuthResult) string {
	for k, v := range commonDeviceStrings {
		if strings.Contains(strings.ToLower(res.SessionOutput), strings.ToLower(v)) {
			return k
		}
	}
	return ""
}
