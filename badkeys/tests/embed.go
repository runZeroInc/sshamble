package tables

import (
	"embed"
)

//go:embed all:*.yml

var TestData embed.FS
