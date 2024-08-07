package badkeys

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"sync"

	"github.com/runZeroInc/sshamble/badkeys/tables"
	"github.com/runZeroInc/sshamble/crypto/ssh"
	"github.com/ulikunitz/xz"
)

var loadTablesOnce = sync.Once{}

type Result struct {
	Repo     string
	RepoID   int8
	RepoType string
	RepoPath string
	RepoName string
	KeyPath  string
}

func (r *Result) ToURL() string {
	if r.RepoType != "github" {
		return ""
	}
	return "https://github.com/" + path.Join(r.Repo, "blob", r.RepoPath, r.KeyPath)
}

func PrefixFromPublicKey(pub ssh.PublicKey) ([]byte, error) {
	var res []byte
	switch pub.Type() {
	case ssh.KeyAlgoRSA:
		pk, ok := pub.(ssh.RSAPublicKey)
		if !ok {
			return nil, fmt.Errorf("%s doesn't implement RSAPublicKey", pub.Type())
		}
		res = pk.ToRSAPublicKey().N.Bytes()
	default:
		res = pub.Marshal()
	}
	hash := sha256.Sum256(res)
	return hash[0:15], nil
}

func LookupPrefix(sum []byte) (*Result, error) {
	if len(sum) < 15 {
		return nil, fmt.Errorf("too short")
	}
	loadTablesOnce.Do(loadTables)
	if loadError != nil {
		return nil, loadError
	}
	block, err := findBlock(sum[0:15])
	if err != nil {
		return nil, err
	}
	if len(block) != BlockLength {
		return nil, fmt.Errorf("wrong length: %d", len(block))
	}
	repo, ok := tableRepos[block[15]]
	if !ok {
		return nil, fmt.Errorf("repo %d is missing", block[15])
	}
	didx := binary.BigEndian.Uint32(block[16:])
	if didx >= uint32(len(tableDirs)) {
		return nil, fmt.Errorf("dir index %d is missing", didx)
	}
	pidx := binary.BigEndian.Uint32(block[16:])
	if pidx >= uint32(len(tablePaths)) {
		return nil, fmt.Errorf("path index %d is missing", pidx)
	}
	return &Result{
		Repo:     repo.Repo,
		RepoID:   int8(repo.ID),
		RepoType: repo.Type,
		RepoPath: repo.Path,
		RepoName: repo.Name,
		KeyPath:  path.Join(tableDirs[didx], tablePaths[pidx]),
	}, nil
}

func findBlock(k []byte) ([]byte, error) {
	i := sort.Search(len(tableBlocks)/BlockLength, func(i int) bool {
		return bytes.Compare(tableBlocks[i*BlockLength:((i+1)*BlockLength)-(BlockLength-BlockHashPrefix)], k) >= 0
	}) * BlockLength

	if i < len(tableBlocks) && bytes.Equal(tableBlocks[i:i+BlockHashPrefix], k) {
		return tableBlocks[i : i+BlockLength], nil
	}
	return nil, fmt.Errorf("not found (%d)", i)
}

var tableBlocks []byte
var tableRepos Repos
var tableDirs Dirs
var tablePaths Paths
var loadError error

func loadTables() {
	fd, err := tables.BadKeys.Open("blocks.dat.xz")
	if err != nil {
		loadError = fmt.Errorf("failed to load blocks.data.xz: %w", err)
		return
	}
	xr, err := xz.NewReader(fd)
	if err != nil {
		loadError = fmt.Errorf("failed to decompress blocks.data.xz: %w", err)
		return
	}
	buff := make([]byte, 1024*1024*4)
	for {
		n, err := xr.Read(buff)
		if err != nil && err != io.EOF {
			loadError = fmt.Errorf("failed to read blocks.data.xz: %w", err)
			return
		}
		if n == 0 {
			break
		}
		tableBlocks = append(tableBlocks, buff[:n]...)
		if err == io.EOF {
			break
		}
	}
	_ = fd.Close()

	fd, err = tables.BadKeys.Open("lookup.dat.xz")
	if err != nil {
		loadError = fmt.Errorf("failed to load lookup.data.xz: %w", err)
		return
	}
	xr, err = xz.NewReader(fd)
	if err != nil {
		loadError = fmt.Errorf("failed to decompress lookup.data.xz: %w", err)
		return
	}
	jdec := json.NewDecoder(xr)
	if err := jdec.Decode(&tableRepos); err != nil {
		loadError = fmt.Errorf("failed to decode repos from lookup.data.xz: %w", err)
		return
	}
	if err := jdec.Decode(&tableDirs); err != nil {
		loadError = fmt.Errorf("failed to decode dirs from lookup.data.xz: %w", err)
		return
	}
	if err := jdec.Decode(&tablePaths); err != nil {
		loadError = fmt.Errorf("failed to decode paths from lookup.data.xz: %w", err)
		return
	}
}
