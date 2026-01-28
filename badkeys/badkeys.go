package badkeys

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const BadKeysMetaURL = "https://update.badkeys.info/v0/badkeysdata.json"

// GetExecutablePath returns the full path to the running binary
func GetExecutablePath() string {
	filename, _ := os.Executable()
	filename, _ = filepath.Abs(filename)
	return filename
}

// GetExecutableDir returns the full path to the running binary's directory
func GetExecutableDir() string {
	return filepath.Dir(GetExecutablePath())
}

func ReadBadKeysManifest(r io.Reader) (*Meta, error) {
	meta := &Meta{}
	jdec := json.NewDecoder(r)
	if err := jdec.Decode(meta); err != nil {
		return meta, fmt.Errorf("decode: %v", err)
	}
	return meta, nil
}
