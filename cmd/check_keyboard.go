package cmd

import (
	"strings"

	"github.com/runZeroInc/sshamble/auth"
	"github.com/runZeroInc/sshamble/crypto/ssh"
)

func sshCheckKeyboardHelper(addr string, tname string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult, testPass string) *auth.AuthResult {
	if !conf.IsCheckEnabled(tname) {
		return nil
	}

	conf.Logger.Debugf("%s %s is running for user %s", addr, tname, options.Username)

	var challName string
	var challQuestions []string
	var challInstruction string

	am := ssh.KeyboardInteractive(func(name string, instr string, questions []string, echos []bool) ([]string, error) {
		if name != "" {
			challName = name
		}
		if instr != "" {
			challInstruction = instr
		}
		if len(questions) > 0 {
			challQuestions = questions
		}
		res := make([]string, len(questions))
		for i := range questions {
			res[i] = testPass
		}
		return res, nil
	})

	res := auth.SSHAuth(addr, options, auth.SSHAuthHandlerSingle(am))

	fmtChall := ""
	if challName != "" {
		fmtChall = "name:" + challName
		if root.KeyboardChallengeName == "" {
			root.KeyboardChallengeName = challName
		}
	}
	if challInstruction != "" {
		if fmtChall != "" {
			fmtChall += " "
		}
		fmtChall += "instruction:" + challInstruction
		if root.KeyboardChallengeInstructions == "" {
			root.KeyboardChallengeInstructions = challInstruction
		}
	}
	if len(challQuestions) != 0 {
		if fmtChall != "" {
			fmtChall += " "
		}
		fmtChall += "questions:" + strings.Join(challQuestions, ",")
		if root.KeyboardChallengeQuestions == "" {
			root.KeyboardChallengeQuestions = strings.Join(challQuestions, ",")
		}
	}

	if res.Stage != "session" {
		conf.Logger.Debugf("%s %s rejected keyboard in stage %s (%s): %v", addr, tname, res.Stage, fmtChall, res.Error)
		return res
	}

	conf.Logger.Warnf("%s %s accepted auth with keyboard password '%s' (%s)", addr, tname, testPass, fmtChall)
	res.SessionMethod = tname
	root.SessionMethod = tname
	root.SessionOutput = res.SessionOutput
	root.SessionSecret = testPass
	root.ExitStatus = res.ExitStatus
	root.SessionAuth = am
	return res
}

const checkKeyboardEmpty = "keyboard-empty"

func sshCheckKeyboardEmpty(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	return sshCheckKeyboardHelper(addr, checkKeyboardEmpty, conf, options, root, "")
}

const checkKeyboardAny = "keyboard-any"

func sshCheckKeyboardAny(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	return sshCheckKeyboardHelper(addr, checkKeyboardAny, conf, options, root, genRandomPassword())
}

const checkKeyboardNull = "keyboard-null"

func sshCheckKeyboardNull(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	return sshCheckKeyboardHelper(addr, checkKeyboardNull, conf, options, root, "\x00")
}

const checkKeyboardUser = "keyboard-user"

func sshCheckKeyboardUser(addr string, conf *ScanConfig, options *auth.Options, root *auth.AuthResult) *auth.AuthResult {
	if gPassword == "" {
		return nil
	}
	return sshCheckKeyboardHelper(addr, checkKeyboardUser, conf, options, root, gPassword)
}

func initKeyboardChecks() {
	registerCheck(checkKeyboardAny, "keyboard", false, true)
	registerCheck(checkKeyboardEmpty, "keyboard", false, true)
	registerCheck(checkKeyboardNull, "keyboard", false, true)
	registerCheck(checkKeyboardUser, "keyboard", false, true)
}
