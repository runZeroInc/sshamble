package badkeys

import (
	"path"
	"strconv"
)

type Result struct {
	Repo     string
	RepoID   int8
	RepoType string
	RepoPath string
	RepoName string
	KeyPath  string
	Private  bool
	Hash     string
}

func (r *Result) GetID() string {
	if r.Private {
		repStr := strconv.FormatUint(uint64(r.RepoID), 10)
		return "badkeys-private-" + repStr + "-" + r.Hash
	}
	return "badkeys-" + r.RepoType + "-" + r.Repo + "-" + r.RepoPath + "-" + r.Hash
}

func (r *Result) GetURL() string {
	if r.Private {
		return "unpublished://" + r.GetID() + "-" + r.Hash
	}
	if r.RepoType != "github" {
		return "https://" + r.RepoType + "/" + path.Join(r.Repo, "blob", r.RepoPath, r.KeyPath)
	}
	return "https://github.com/" + path.Join(r.Repo, "blob", r.RepoPath, r.KeyPath)
}
