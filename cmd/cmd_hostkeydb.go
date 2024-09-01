package cmd

import (
	"bufio"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/sshamble/auth"
	"github.com/runZeroInc/sshamble/badkeys"
	"github.com/runZeroInc/sshamble/crypto/ssh"
	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"
)

// hostkeydbCmd processes a scan output file and buckets results
var hostkeydbCmd = &cobra.Command{
	Use:   "hostkeydb -o results-directory scan.json ...",
	Short: "Analyzes a scan JSON output file and produces a hostkey DB",
	Long:  "Analyzes a scan JSON output file and produces a hostkey DB",
	Run:   runHostkeyDB,
}

func init() {
	hostkeydbCmd.Flags().StringVarP(&gOutput, "output", "o", "", "The output database filename")
	hostkeydbCmd.Flags().StringVarP(&gLogfile, "log", "l", "-", "The file to write logs to (default is stderr)")
	hostkeydbCmd.Flags().StringVarP(&gLogLevel, "log-level", "L", "debug", "The log level to write (trace,debug,info,warn,error)")
}

const DBBatchSize = 100000

func runHostkeyDB(cmd *cobra.Command, args []string) {
	conf := &ScanConfig{}
	configureLogging(conf)

	var tx *sql.Tx
	var stmt *sql.Stmt
	var err error

	if gOutput == "" || gOutput == "-" || gOutput == "stdout" {
		conf.Logger.Fatalf("no output directory supplied (-o)")
	}

	if len(args) < 1 {
		conf.Logger.Fatalf("no input files specified")
	}

	db, err := sql.Open("sqlite", gOutput)
	if err != nil {
		conf.Logger.Fatalf("failed to open db: %v", err)
	}

	start := time.Now()

	if _, err = db.Exec(`
			pragma synchronous = OFF;
			pragma journal_mode = OFF;
			drop table if exists hostkeys;
			create table hostkeys(hash blob, ts integer, host blob, port integer);
		`); err != nil {
		conf.Logger.Fatalf("failed to create db schema: %v", err)
	}

	openTx := func() {
		if tx != nil {
			conf.Logger.Fatalf("db tx already open")
		}
		tx, err = db.Begin()
		if err != nil {
			conf.Logger.Fatalf("failed to create db tx: %v", err)
		}
		stmt, err = tx.Prepare("insert into hostkeys(hash, ts, host, port) values (?, ?, ?, ?)")
		if err != nil {
			conf.Logger.Fatalf("db prepare: %v", err)
		}
	}

	closeTx := func() {
		if tx != nil {
			if err = stmt.Close(); err != nil {
				conf.Logger.Fatalf("db close: %v", err)
			}

			if err = tx.Commit(); err != nil {
				conf.Logger.Fatalf("commit: %v", err)
			}
			tx = nil
		}
	}

	openTx()

	hcache := make(map[string]struct{})

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
			res := auth.AuthResult{}
			if err := json.Unmarshal([]byte(line), &res); err != nil {
				conf.Logger.Errorf("%s: failed to parse line: %s (%v)", inp, line, err)
			}

			endp := res.Host + strconv.Itoa(res.Port)
			for _, hkv := range res.HostKeys {
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

				if _, found := hcache[endp+"/"+string(hpre)]; found {
					continue
				}

				if _, err = stmt.Exec(hpre, res.TS, []byte(net.ParseIP(res.Host)), res.Port); err != nil {
					conf.Logger.Fatalf("db insert: %v", err)
				}

				cnt++
				if cnt%DBBatchSize == 0 {
					conf.Logger.Infof("writing batch at %d results", cnt)
					closeTx()
					openTx()
				}

				hcache[endp+"/"+string(hpre)] = struct{}{}
			}
		}
	}
	closeTx()

	fmt.Println("creating the index...")

	if _, err := db.Exec(`create index hostkeys_hash_idx on hostkeys (hash)`); err != nil {
		conf.Logger.Fatalf("db index: %v", err)
	}

	conf.Logger.Printf("done in %v", time.Since(start))

	if err = db.Close(); err != nil {
		conf.Logger.Fatalf("db close: %v", err)
	}

	fi, err := os.Stat(gOutput)
	if err != nil {
		conf.Logger.Fatalf("db stat: %v", err)
	}

	conf.Logger.Printf("%s db size: %v", gOutput, fi.Size())
}
