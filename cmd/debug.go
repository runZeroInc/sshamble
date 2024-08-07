package cmd

import "github.com/mmcloughlin/professor"

func startProfiler() {
	if gPProfPort != "" {
		professor.Launch("127.0.0.1:" + gPProfPort)
	}
}
