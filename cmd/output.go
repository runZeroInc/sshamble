package cmd

import (
	"encoding/json"
	"runtime"
	"time"

	"github.com/runZeroInc/sshamble/auth"
)

func (conf *ScanConfig) WriteOutput(res *auth.AuthResult) {
	conf.outMutex.Lock()
	defer conf.outMutex.Unlock()

	resb, err := json.Marshal(res)
	if err != nil {
		conf.Logger.Errorf("failed to serialize %v: %v", res, err)
		return
	}
	resb = append(resb, '\n')

	for {
		if _, err = conf.OutputWriter.Write(resb); err == nil {
			conf.statResult.Add(1)
			break
		}
		conf.Logger.Errorf("failed to write, sleeping...")
		time.Sleep(time.Second)
	}
}

// getStackTrace returns a dump of all goroutine stacks
func getStackTrace(maxLength int) string {
	stacktrace := make([]byte, maxLength)
	length := runtime.Stack(stacktrace, true)
	return string(stacktrace[:length])
}
