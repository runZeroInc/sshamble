package badkeys

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"path"
	"sort"
)

const BlockLength = 16
const BlockHashPrefix = 15

type Meta struct {
	BKFormat        int    `json:"bkformat,omitempty"`
	Date            string `json:"date,omitempty"`
	BlocklistURL    string `json:"blocklist_url,omitempty"`
	BlocklistSHA256 string `json:"blocklist_sha256,omitempty"`
	LookupURL       string `json:"lookup_url,omitempty"`
	LookupSHA256    string `json:"lookup_sha256,omitempty"`
	Blocklists      []Repo `json:"blocklists,omitempty"`
}

type Repo struct {
	ID   int    `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
	Repo string `json:"repo,omitempty"`
	Path string `json:"path,omitempty"`
}

type Repos map[int]Repo
type Dirs []string
type Paths []string

type Blocklist struct {
	Meta          *Meta
	Blocks        []byte
	Repos         Repos
	LookupMap     map[uint64][]int
	LookupStrings []string
	Error         error
}

func NewBlocklist() *Blocklist {
	return &Blocklist{
		LookupMap: make(map[uint64][]int),
		Repos:     make(Repos),
	}
}

func (tset *Blocklist) FindBlock(k []byte) ([]byte, error) {
	i := sort.Search(len(tset.Blocks)/BlockLength, func(i int) bool {
		return bytes.Compare(tset.Blocks[i*BlockLength:((i+1)*BlockLength)-(BlockLength-BlockHashPrefix)], k) >= 0
	}) * BlockLength
	if i < len(tset.Blocks) && bytes.Equal(tset.Blocks[i:i+BlockHashPrefix], k) {
		return tset.Blocks[i : i+BlockLength], nil
	}
	return nil, fmt.Errorf("not found (%d)", i)
}

func (tset *Blocklist) LookupPrefix(sum []byte) (*Result, error) {
	if len(sum) < 15 {
		return nil, fmt.Errorf("too short")
	}
	block, err := tset.FindBlock(sum[0:15])
	if err != nil {
		return nil, err
	}
	if len(block) != BlockLength {
		return nil, fmt.Errorf("wrong length: %d", len(block))
	}
	repo, ok := tset.Repos[int(block[15])]
	if !ok {
		return nil, fmt.Errorf("repo %d is missing", block[15])
	}
	info, ok := tset.LookupMap[binary.BigEndian.Uint64(block[:8])]
	if !ok {
		return nil, fmt.Errorf("lookup %x is missing", block[:8])
	}
	parts := make([]string, len(info))
	for i, lk := range info {
		parts[i] = tset.LookupStrings[lk]
	}

	return &Result{
		Repo:     repo.Repo,
		RepoID:   int8(repo.ID),
		RepoType: repo.Type,
		RepoPath: repo.Path,
		RepoName: repo.Name,
		KeyPath:  path.Join(parts...),
	}, nil
}
