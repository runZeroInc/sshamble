package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/runZeroInc/sshamble/badkeys"
	"github.com/sirupsen/logrus"
	"github.com/ulikunitz/xz"
)

func httpGet(url string, timeout time.Duration) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("http req %s: %v", url, err)
	}
	ctx, _ := context.WithTimeout(req.Context(), timeout)
	req = req.WithContext(ctx)
	req.Header.Add("User-Agent", "python-requests/2.28.2")
	client := http.DefaultClient
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get %s: %v", url, err)
	}
	return res, nil
}

func main() {
	// Create the output directory of needed
	if err := os.MkdirAll("tables", 0o755); err != nil {
		logrus.Fatalf("could not create data directory: %v", err)
	}

	// Grab the metadata to obtain the repo IDs, categories, blocklist & lookup URLs
	res, err := httpGet(badkeys.BadKeysMetaURL, time.Second*30)
	if err != nil {
		logrus.Fatalf("failed to obtain metadata: %v", err)
	}
	meta := &badkeys.Meta{}
	jdec := json.NewDecoder(res.Body)
	if err := jdec.Decode(meta); err != nil {
		logrus.Fatalf("failed to decode metadata: %v", err)
	}
	_ = res.Body.Close()

	// Build the repo lookup map
	repos := make(badkeys.Repos)
	for _, v := range meta.Blocklists {
		repos[uint8(v.ID)] = v
	}

	// Grab the lookup data and build maps
	sha8 := make(map[string][]uint32)
	res, err = httpGet(meta.LookupURL, time.Hour)
	if err != nil {
		logrus.Fatalf("failed to obtain lookup from %s: %v", meta.LookupURL, err)
	}

	hitDirs := make(map[string]uint32)
	dirIdx := uint32(0)

	hitPaths := make(map[string]uint32)
	pathIdx := uint32(0)

	// Parse each line
	xr, err := xz.NewReader(res.Body)
	if err != nil {
		logrus.Fatalf("failed to decompress lookup file: %v", err)
	}
	buff := make([]byte, 1024*16)
	scan := bufio.NewScanner(xr)
	scan.Buffer(buff, 1024*16)
	for scan.Scan() {
		if scan.Err() != nil {
			logrus.Fatalf("failed to scan lookup file: %v", err)
		}
		line := strings.TrimSpace(scan.Text())
		if line == "" {
			continue
		}
		hash, fpath, ok := strings.Cut(line, ";")
		if !ok {
			continue
		}

		fDir := path.Dir(fpath)
		if _, ok := hitDirs[fDir]; !ok {
			hitDirs[fDir] = dirIdx
			dirIdx++
		}

		fPath := path.Base(fpath)
		if _, ok := hitPaths[fPath]; !ok {
			hitPaths[fPath] = pathIdx
			pathIdx++
		}
		// Store the sha-8 truncated hash key mapping to the index IDs of the dir and path
		sha8[hash] = []uint32{hitDirs[fDir], hitPaths[fPath]}
	}

	// Build an in-order lookup table for directories
	dirTable := make(badkeys.Dirs, len(hitDirs))
	for k, v := range hitDirs {
		dirTable[v] = k
	}

	// Build an in-order lookup table for paths
	pathTable := make(badkeys.Paths, len(hitPaths))
	for k, v := range hitPaths {
		pathTable[v] = k
	}

	logrus.Printf("loaded %d keys (%d dirs, %d paths)", len(sha8), len(dirTable), len(pathTable))

	// Grab the blocklist and decode the mapping of sha256 to repo ID
	res, err = httpGet(meta.BlocklistURL, time.Hour)
	if err != nil {
		logrus.Fatalf("failed to obtain lookup from %s: %v", meta.LookupURL, err)
	}

	// Output []byte{24}[ 0 .. 15 | 1 | 4 | 4 ] <sha256-15trunc, repoID, prefixID, fileID>
	// Sort this into blocks of 24 and then binary search, looking up repo, prefix, and file
	blocks := [][]byte{}

	// Each block is a 15-byte truncated SHA256 with a 1-byte repo ID
	xr, err = xz.NewReader(res.Body)
	if err != nil {
		logrus.Fatalf("failed to decompress blocklist file: %v", err)
	}
	for idx := 0; ; idx++ {
		block := make([]byte, 24)
		n, err := xr.Read(block[0:16])
		if err != nil && err != io.EOF {
			logrus.Fatalf("failed to read block %d: %v", idx, err)
		}
		if n == 0 {
			break
		}
		if n != 16 {
			logrus.Fatalf("failed to read block %d: short %d", idx, n)
		}
		if err == io.EOF {
			break
		}

		// Verify the repository ID
		_, ok := repos[block[badkeys.BlockHashPrefix]]
		if !ok {
			logrus.Errorf("block %d references missing repo %d (%s)", idx, block[badkeys.BlockHashPrefix], hex.EncodeToString(block[0:24]))
			continue
		}

		// Verify the hash
		lk := hex.EncodeToString(block[0:8])
		lv, ok := sha8[lk]
		if !ok {
			logrus.Errorf("block %d references missing hash %s", idx, lk)
			continue
		}

		// Store the directory ID
		binary.BigEndian.PutUint32(block[16:], lv[0])

		// Store the path ID
		binary.BigEndian.PutUint32(block[20:], lv[1])

		// Add this to our block list
		blocks = append(blocks, block)
	}

	logrus.Printf("loaded %d blocks", len(blocks))

	// Sort the blocks in order
	sort.SliceStable(blocks, func(i, j int) bool {
		return bytes.Compare(blocks[i], blocks[j]) == -1
	})

	// Write the blocks
	fd, err := os.Create("tables/blocks.dat.xz")
	if err != nil {
		logrus.Fatalf("could not create blocks.dat.xz: %v", err)
	}
	xw, err := xz.NewWriter(fd)
	if err != nil {
		logrus.Fatalf("could not create xz for blocks.dat.xz: %v", err)
	}
	for _, v := range blocks {
		_, err = xw.Write(v)
		if err != nil {
			logrus.Fatalf("could not write blocks.dat.xz: %v", err)
		}
	}
	if err := xw.Close(); err != nil {
		logrus.Fatalf("could not close xz for blocks.dat.xz: %v", err)
	}
	if err := fd.Close(); err != nil {
		logrus.Fatalf("could not close blocks.dat.xz: %v", err)
	}

	// Write the lookup tables
	fd, err = os.Create("tables/lookup.dat.xz")
	if err != nil {
		logrus.Fatalf("could not create lookup.dat.xz: %v", err)
	}
	xw, err = xz.NewWriter(fd)
	if err != nil {
		logrus.Fatalf("could not create xz for lookup.dat.xz: %v", err)
	}
	jenc := json.NewEncoder(xw)
	if err := jenc.Encode(repos); err != nil {
		logrus.Fatalf("could not write lookup.dat.xz: repos %v", err)
	}
	if err := jenc.Encode(dirTable); err != nil {
		logrus.Fatalf("could not write lookup.dat.xz: dirs %v", err)
	}
	if err := jenc.Encode(pathTable); err != nil {
		logrus.Fatalf("could not write lookup.dat.xz: paths %v", err)
	}
	if err := xw.Close(); err != nil {
		logrus.Fatalf("could not close xz for lookup.dat.xz: %v", err)
	}
	if err := fd.Close(); err != nil {
		logrus.Fatalf("could not close lookup.dat.xz: %v", err)
	}
}
