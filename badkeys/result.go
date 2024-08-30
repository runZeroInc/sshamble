package badkeys

import "path"

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
