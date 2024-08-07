package badkeys

const BadKeysMetaURL = "https://update.badkeys.info/v0/badkeysdata.json"

const BlockLength = 24
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

type Repos map[uint8]Repo
type Dirs []string
type Paths []string
