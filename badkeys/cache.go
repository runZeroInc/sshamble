package badkeys

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/runZeroInc/excrypto/crypto/sha256"

	"github.com/sirupsen/logrus"
	"github.com/ulikunitz/xz"
)

const MaxLookupLine = 4096
const MaxResponseSize = 1024 * 1024 * 512 // Adjust if the block list becomes larger
const CacheFileMetadata = "badkeysdata.json"
const CacheFileBlocklist = "blocklist.dat"
const CacheFileLookup = "lookup.txt"
const HTTPDataDownloadTimeout = time.Hour
const HTTPMetaDownloadTimeout = time.Second * 30

type Cache struct {
	sync.Mutex
	Blocklist *Blocklist
	LoadError error
	cacheDir  string
	lgr       *logrus.Logger
}

func NewCache(lgr *logrus.Logger) *Cache {
	return &Cache{lgr: lgr}
}

// LoadBlocklist loads the blocklist from disk if necessary
func (cache *Cache) LoadBlocklist() (*Blocklist, error) {
	cache.Lock()
	defer cache.Unlock()
	if cache.Blocklist != nil {
		return cache.Blocklist, cache.LoadError
	}
	cache.Blocklist, cache.LoadError = cache.loadBlocklistFromDisk()
	return cache.Blocklist, cache.LoadError
}

// loadBlocklistFromDisk returns block lists from the local cache directory
func (cache *Cache) loadBlocklistFromDisk() (*Blocklist, error) {
	tset := NewBlocklist()

	// Load the metadata
	rdr, err := cache.OpenFile(CacheFileMetadata)
	if err != nil {
		return nil, fmt.Errorf("manifest open: %v", err)
	}
	meta, err := ReadBadKeysManifest(rdr)
	if err != nil {
		_ = rdr.Close()
		return nil, fmt.Errorf("manifest: %v", err)
	}
	tset.Meta = meta
	_ = rdr.Close()

	for _, repo := range meta.Blocklists {
		tset.Repos[repo.ID] = repo
	}

	// Load the block list
	rdr, err = cache.OpenFile(CacheFileBlocklist)
	if err != nil {
		return nil, fmt.Errorf("blocklist open: %v", err)
	}
	buff, err := io.ReadAll(rdr)
	if err != nil {
		_ = rdr.Close()
		return nil, fmt.Errorf("blocklist: %v", err)
	}
	tset.Blocks = buff
	_ = rdr.Close()

	// Load the lookup list
	rdr, err = cache.OpenFile(CacheFileLookup)
	if err != nil {
		return nil, fmt.Errorf("lookup open: %v", err)
	}

	lmap := make(map[uint64][]int)
	smap := make(map[string]int)
	smapIdx := 0

	scan := bufio.NewScanner(rdr)
	buff = make([]byte, MaxLookupLine)
	scan.Buffer(buff, MaxLookupLine)
	for scan.Scan() {
		kid, kpath, ok := strings.Cut(scan.Text(), ";")
		if !ok {
			continue
		}
		kint, err := strconv.ParseUint(kid, 16, 64)
		if err != nil {
			cache.lgr.Errorf("invalid key id %s: %v", kid, err)
			continue
		}
		bits := strings.Split(kpath, "/")
		lset := make([]int, len(bits))
		for i, kdir := range bits {
			sid, found := smap[kdir]
			if !found {
				smap[kdir] = smapIdx
				sid = smapIdx
				smapIdx++
			}
			lset[i] = sid
		}
		lmap[kint] = lset
	}
	sset := make([]string, len(smap))
	for k, i := range smap {
		sset[i] = k
	}
	tset.LookupMap = lmap
	tset.LookupStrings = sset
	return tset, nil
}

// SetCacheDir sets the location of the badkeys block tables
func (cache *Cache) SetCacheDir(s string) {
	cache.cacheDir = s
}

// GetCacheDir returns the location of the badkeys block tables
func (cache *Cache) GetCacheDir() string {

	if cache.cacheDir != "" {
		return cache.cacheDir
	}

	base := os.Getenv("HOME")
	if _, err := os.Stat(base); err != nil || base == "" {
		base = GetExecutableDir()
	}
	cache.cacheDir = filepath.Join(base, ".cache", "badkeys")
	return cache.cacheDir
}

// OpenFile returns a reader for the given cache file name
func (cache *Cache) OpenFile(path string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(cache.GetCacheDir(), filepath.Base(path)))
}

// CreateFile returns a writer for the given cache file name
func (cache *Cache) CreateFile(path string) (io.WriteCloser, error) {
	_ = os.MkdirAll(cache.GetCacheDir(), 0o755)
	return os.Create(filepath.Join(cache.GetCacheDir(), filepath.Base(path)))
}

// RemoveFile deletes a file from the cache
func (cache *Cache) RemoveFile(path string) error {
	return os.Remove(filepath.Join(cache.GetCacheDir(), filepath.Base(path)))
}

// RenameFile replaces one file with another in the caache
func (cache *Cache) RenameFile(src string, dst string) error {
	_ = os.Remove(filepath.Join(cache.GetCacheDir(), filepath.Base(dst)))
	return os.Rename(
		filepath.Join(cache.GetCacheDir(), filepath.Base(src)),
		filepath.Join(cache.GetCacheDir(), filepath.Base(dst)),
	)
}

func (cache *Cache) CurrentMetadata() (*Meta, error) {
	rdr, err := cache.OpenFile(CacheFileMetadata)
	if err != nil {
		return nil, err
	}
	defer rdr.Close()
	return ReadBadKeysManifest(rdr)
}

func (cache *Cache) Update() (string, string, error) {
	var pre, cur string

	// Grab the metadata to obtain the repo IDs, categories, blocklist & lookup URLs
	body, err := httpGetData(BadKeysMetaURL, HTTPMetaDownloadTimeout)
	if err != nil {
		return pre, cur, fmt.Errorf("failed to retrieve %s: %w", BadKeysMetaURL, err)
	}
	meta := &Meta{}
	if err := json.Unmarshal(body, meta); err != nil {
		return pre, cur, fmt.Errorf("failed to decode %s: %w", BadKeysMetaURL, err)
	}
	cur = meta.Date

	// Remove any temporary files on early exit due to error
	tmpFiles := []string{}
	defer func() {
		for _, path := range tmpFiles {
			_ = cache.RemoveFile(path)
		}
	}()

	// Refactor into better validation
	if !(strings.HasPrefix(meta.BlocklistURL, "http://") || strings.HasPrefix(meta.BlocklistURL, "https://")) {
		return pre, cur, fmt.Errorf("bad blocklist url %s", meta.BlocklistURL)
	}
	if !(strings.HasPrefix(meta.LookupURL, "http://") || strings.HasPrefix(meta.LookupURL, "https://")) {
		return pre, cur, fmt.Errorf("bad lookup url %s", meta.BlocklistURL)
	}

	// Write temporary metadata to disk
	w, err := cache.CreateFile(CacheFileMetadata + ".tmp")
	if err != nil {
		return pre, cur, fmt.Errorf("failed to create metadata %s: %w", CacheFileMetadata+".tmp", err)
	}
	tmpFiles = append(tmpFiles, CacheFileMetadata+".tmp")
	if _, err := w.Write(body); err != nil {
		_ = w.Close()
		return pre, cur, fmt.Errorf("failed to write metadata %s: %w", CacheFileMetadata+".tmp", err)
	}
	if err := w.Close(); err != nil {
		return pre, cur, fmt.Errorf("failed to close metadata %s: %w", CacheFileMetadata+".tmp", err)
	}

	// Compare the metadata with the cached version
	if oldMeta, err := cache.CurrentMetadata(); err == nil {
		pre = oldMeta.Date
		if oldMeta.Date == meta.Date {
			return pre, cur, nil
		}
	}

	// Download, validate, decompress, and write the blocklist file
	if err := cache.DownloadAndValidateXZ(meta.BlocklistURL, meta.BlocklistSHA256, CacheFileBlocklist+".tmp"); err != nil {
		return pre, cur, err
	}
	tmpFiles = append(tmpFiles, CacheFileBlocklist+".tmp")

	// Download, validate, decompress, and write the lookup file
	if err := cache.DownloadAndValidateXZ(meta.LookupURL, meta.LookupSHA256, CacheFileLookup+".tmp"); err != nil {
		return pre, cur, err
	}
	tmpFiles = append(tmpFiles, CacheFileLookup+".tmp")

	// Write the new files to disk
	if err := cache.RenameFile(CacheFileBlocklist+".tmp", CacheFileBlocklist); err != nil {
		return pre, cur, err
	}
	if err := cache.RenameFile(CacheFileLookup+".tmp", CacheFileLookup); err != nil {
		return pre, cur, err
	}
	if err := cache.RenameFile(CacheFileMetadata+".tmp", CacheFileMetadata); err != nil {
		return pre, cur, err
	}

	return pre, cur, nil
}

func (cache *Cache) DownloadAndValidateXZ(u string, hash string, path string) error {
	res, cancel, err := httpGet(u, HTTPDataDownloadTimeout)
	defer cancel()

	if err != nil {
		return fmt.Errorf("download failed for %s: %w", path, err)
	}
	defer res.Body.Close()

	w, err := cache.CreateFile(path)
	if err != nil {
		return fmt.Errorf("create failed for %s: %w", path, err)
	}
	cleanup := func() {
		w.Close()
		cache.RemoveFile(path)
	}

	h := sha256.New()
	r, err := xz.NewReader(res.Body)
	if err != nil {
		cleanup()
		return fmt.Errorf("xz read failed for %s: %w", path, err)
	}
	if _, err = io.Copy(io.MultiWriter(w, h), r); err != nil {
		cleanup()
		return fmt.Errorf("read failed for %s: %w", path, err)
	}
	if err := w.Close(); err != nil {
		cleanup()
		return fmt.Errorf("write failed for %s: %w", path, err)
	}

	bodyHashExp, err := hex.DecodeString(hash)
	if err != nil {
		cleanup()
		return fmt.Errorf("bad sha256 for %s in metadata: %w", path, err)
	}

	bodyHashGot := h.Sum(nil)
	if !bytes.Equal(bodyHashExp, bodyHashGot[:]) {
		cleanup()
		return fmt.Errorf("bad sha256 for %s, expected %s and got %s", path, hash, hex.EncodeToString(bodyHashGot[:]))
	}
	return nil
}
