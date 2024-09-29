package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/runZeroInc/excrypto/x/crypto/ssh"
	"github.com/runZeroInc/sshamble/auth"
	"golang.org/x/term"
)

const (
	interactCommandByteName = "^E"
	interactCommandByte     = 0x05 // ^E  (enquiry)
)

func (conf *ScanConfig) StartInteract(addr string, options *auth.Options, root *auth.AuthResult) error {
	interactMutex.Lock()
	defer interactMutex.Unlock()

	// Disable session poke defaults for interaction
	options = options.
		WithSessionHandler(conf.InteractHandler(addr, options, root)).
		WithSessionPoke("").
		WithRetries(10)

	var res *auth.AuthResult
	if root.SessionAuth != nil {
		// Use the ssh.AuthMethod cached on the root session
		res = auth.SSHAuth(addr, options.WithSessionHandler(conf.InteractHandler(addr, options, root)), auth.SSHAuthHandlerSingle(root.SessionAuth))
	} else {
		switch root.SessionMethod {
		case checkSkipSSHUserAuth:
			res = sshCheckSkipUserAuthService(addr, conf, options, root)
		case checkSkipAuth:
			res = sshCheckSkipAuth(addr, conf, options, root)
		case checkSkipAuthNone:
			res = sshCheckSkipAuthNone(addr, conf, options, root)
		case checkSkipAuthPubkeyAny:
			res = sshCheckSkipAuthPubkeyAny(addr, conf, options, root)
		case checkSkipAuthSuccess:
			res = sshCheckSkipAuthSuccess(addr, conf, options, root)
		default:
			return fmt.Errorf("interact is not yet implemented for %s", root.SessionMethod)
		}
	}
	if res == nil {
		return nil
	}
	conf.Logger.Debugf("%s session interaction complete", addr)
	if res.Error == "" {
		return nil
	}
	return errors.New(res.Error)
}

var gStdinManager *stdinManager

type stdinManager struct {
	sync.Mutex
	output   chan []byte
	origMode *term.State
	rawMode  bool
}

func NewStdinManager() *stdinManager {
	m := &stdinManager{
		output: nil,
	}
	return m
}

func (m *stdinManager) CleanTerminal() {
	// Disable bracketed-paste mode
	os.Stdout.Write([]byte("\x1b[?2004l"))
	os.Stdout.Sync()
}

func (m *stdinManager) SetOutput(w chan []byte) {
	m.Lock()
	defer m.Unlock()
	m.output = w
}

func (m *stdinManager) SetRawTerminalMode() {
	m.Lock()
	defer m.Unlock()
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return
	}
	old, err := term.MakeRaw(fd)
	if err != nil {
		fmt.Printf("Error: stdin manager failed to set raw mode: %v\r\n", err)
		return
	}
	if m.origMode == nil {
		m.origMode = old
	}
	m.rawMode = true
}

func (m *stdinManager) RestoreTerminalMode() {
	m.Lock()
	defer m.Unlock()
	fd := int(os.Stdin.Fd())
	if !(term.IsTerminal(fd) && m.rawMode) {
		return
	}
	if err := term.Restore(fd, m.origMode); err != nil {
		fmt.Printf("Error: stdin manager failed to restore terminal mode: %v\r\n", err)
	}
	m.rawMode = false
}

func (m *stdinManager) IsRawMode() bool {
	m.Lock()
	defer m.Unlock()
	return m.rawMode
}

func (m *stdinManager) Relay(conf *ScanConfig, ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			conf.Logger.Errorf("panic: relay: %v", r)
		}
		m.RestoreTerminalMode()
	}()

	m.SetRawTerminalMode()
	m.CleanTerminal()

	next := make([]byte, 1)
	buff := []byte{}

	tick := time.NewTicker(time.Second / 10)
	defer tick.Stop()

StdinRelayLoop:
	for {

		select {
		case <-ctx.Done():
			break StdinRelayLoop
		case <-tick.C:
		}

		_ = os.Stdin.SetReadDeadline(time.Now().Add(time.Second / 10))
		n, err := os.Stdin.Read(next)
		if err == context.DeadlineExceeded {
			continue
		}

		m.Lock()
		h := m.output
		m.Unlock()

		if err != nil {
			conf.Logger.Debugf("stdin manager read failed: %s", err)
			return
		}
		if n == 0 {
			conf.Logger.Debugf("stdin manager read returned 0")
			return
		}

		if h == nil {
			// No output to write to, dump to stdout as local echo instead
			_, _ = os.Stdout.Write(next)
			os.Stdout.Sync()
			continue
		}

		c := next[0]

		// Raw mode
		if m.IsRawMode() {
			if c == interactCommandByte {
				m.CleanTerminal()

				// Enter command mode
				fmt.Printf("\r\n sshamble> ")
				os.Stdout.Sync()
				m.RestoreTerminalMode()
				buff = []byte{c}
				continue
			}
			h <- []byte{c}
			buff = []byte{}
			continue
		}

		// Command mode
		buff = append(buff, c)
		if c == '\r' || c == '\n' {
			h <- []byte(buff)
			m.SetRawTerminalMode()
			buff = []byte{}
			continue
		}
	}
}

type interactSessionState struct {
	sync.Mutex
	pty     bool
	started bool
	shell   bool
}

func (state *interactSessionState) Pty() bool {
	state.Lock()
	defer state.Unlock()
	return state.pty
}

func (state *interactSessionState) Started() bool {
	state.Lock()
	defer state.Unlock()
	return state.started
}

func (state *interactSessionState) Shell() bool {
	state.Lock()
	defer state.Unlock()
	return state.shell
}

func (state *interactSessionState) SetPty() {
	state.Lock()
	defer state.Unlock()
	state.pty = true
}

func (state *interactSessionState) SetStarted() {
	state.Lock()
	defer state.Unlock()
	state.started = true
}

func (state *interactSessionState) SetShell() {
	state.Lock()
	defer state.Unlock()
	state.shell = true
}

func (conf *ScanConfig) InteractHandler(addr string, options *auth.Options, root *auth.AuthResult) auth.SessionHandler {
	return func(conn net.Conn, sclient *ssh.Client, ses *ssh.Session, res *auth.AuthResult) error {
		intDoneCtx, intDoneCancel := context.WithCancel(context.Background())
		defer intDoneCancel()

		// Force a socket close at a fixed timeout to prevent hangs
		go func() {
			defer func() {
				if r := recover(); r != nil {
					conf.Logger.Errorf("panic: ssh close handler for %s %v", addr, r)
				}
			}()
			auth.CloseAfterTimeout(intDoneCtx, time.Hour, addr, conn)
		}()

		fd := int(os.Stdin.Fd())
		if !term.IsTerminal(fd) {
			return fmt.Errorf("interact mode requires a controlling terminal")
		}

		go gStdinManager.Relay(conf, intDoneCtx)

		state := &interactSessionState{}

		sesInput, err := ses.StdinPipe()
		if err != nil {
			return fmt.Errorf("failed to get stdin pipe: %v", err)
		}
		defer sesInput.Close()

		sesOutput := NewSessionOutputWriter(os.Stdout)
		ses.Stdout = sesOutput
		ses.Stderr = sesOutput

		quit := make(chan bool, 1)

		defer func() {
			close(quit)
		}()

		// Make sure our terminal is in raw mode
		if !gStdinManager.IsRawMode() {
			gStdinManager.SetRawTerminalMode()
		}
		defer gStdinManager.RestoreTerminalMode()

		// Close the ssh.Client first (last defer) to avoid deadlocks
		defer sclient.Close()

		// Start piping our raw-mode stdin manager
		go conf.InteractRelay(addr, quit, sesInput, sclient, ses, state)

		for _, cmd := range strings.Split(gInteractAuto, ",") {
			cmd = strings.TrimSpace(cmd)
			if cmd == "" {
				continue
			}
			fmt.Printf(" sshamble> " + cmd + "\r\n")
			spawned, err := conf.InteractCommand(addr, []byte(cmd), ses, sclient, state, sesInput)
			if err != nil {
				conf.Logger.Errorf("%s command '%s' returned error: %v", addr, cmd, err)
				if err == io.EOF {
					return err
				}
			}
			if strings.HasPrefix(cmd, "pty") && err == nil {
				state.SetPty()
			}
			if spawned && err == nil {
				conf.Logger.Infof("%s session spawned a subprocess", addr)
				state.SetStarted()
			}
		}

		conf.InteractShowHelp(addr)

		if !state.Started() {
			fmt.Printf("\r\nNo subcommand or subsystem has started yet (use %s, then 'pty' then 'shell').\r\n", interactCommandByteName)
		}

		if state.Started() && !state.Pty() {
			fmt.Printf("\r\nNo pty was allocated and no i/o is available as a result.\r\n")
		}

		for {
			if ses.Started() {
				break
			}
			time.Sleep(time.Second / 5)
			if ses.Closed() {
				return nil
			}
		}

		conf.Logger.Infof("waiting for session to complete...")
		if err := ses.Wait(); err != nil {
			sclient.Close()
			sesInput.Close()
		}
		gStdinManager.RestoreTerminalMode()
		return nil
	}
}

func (conf *ScanConfig) InteractShowHelp(addr string) {
	fmt.Printf("\r\n\r\nInteracting with session on %s\r\n\r\n", addr)
	fmt.Printf("  Enter the sshamble shell with `%s`. Commands:\r\n\r\n", interactCommandByteName)
	fmt.Printf("    exit                       - Exit the session (aliases 'quit' or '.')\r\n")
	fmt.Printf("    help                       - Show this help text (alias '?')\r\n")
	fmt.Printf("    env      a=1 b=2           - Set the specified environment variables (-w for wait mode)\r\n")
	fmt.Printf("    pty                        - Request a pty on the remote session (-w for wait mode)\r\n")
	fmt.Printf("    shell                      - Request the default shell on the session\r\n")
	fmt.Printf("    exec     cmd arg1 arg2     - Request non-interactive command on the session\r\n")
	fmt.Printf("    signal   sig1 sig2         - Send one or more signals to the subprocess, case-sensitive:\r\n")
	fmt.Printf("                                 %s\r\n", strings.Join(sshValidSignals, ","))
	fmt.Printf("    tcp      host port         - Make a test connection to a TCP host and port\r\n")
	fmt.Printf("    unix     path              - Make a test connection to a Unix stream socket\r\n")
	fmt.Printf("    break    milliseconds      - Send a 'break' request to the service\r\n")
	fmt.Printf("    req      cmd arg1 arg2     - Send a custom SSH request to the service\r\n")
	fmt.Printf("    sub      subsystem         - Request a specific subsystem\r\n")
	fmt.Printf("    send     string            - Send string to the session\r\n")
	fmt.Printf("    sendb    string            - Send string to the session one byte at a time\r\n")
	fmt.Printf("    wait     cmd arg1 arg2     - Send another command and wait for a reply\r\n")
	fmt.Printf("\r\n\r\n")
}

func (conf *ScanConfig) InteractRelay(addr string, quit chan bool, shell io.WriteCloser, sclient *ssh.Client, ses *ssh.Session, state *interactSessionState) {
	input := make(chan []byte, 1)
	gStdinManager.SetOutput(input)

	defer func() {
		if r := recover(); r != nil {
			conf.Logger.Errorf("panic: interact relay: %v", r)
		}
		gStdinManager.SetOutput(nil)
		sclient.Close()
	}()

	for {
		select {
		case <-quit:
			return
		case c, ok := <-input:
			if !ok {
				return
			}

			// Command byte prefix indicates command mode and a full line of input
			if bytes.HasPrefix(c, []byte{interactCommandByte}) {
				// Double byte means send a literal command-byte to the session
				if len(c) > 1 && c[1] == interactCommandByte {
					if _, err := shell.Write([]byte{c[1]}); err != nil {
						conf.Logger.Debugf("%s session write failed: %v", addr, err)
						return
					}
					continue
				}

				c = bytes.TrimPrefix(c, []byte{interactCommandByte})
				c = bytes.TrimSpace(c)
				if len(c) == 0 {
					conf.Logger.Debugf("%s empty command", addr)
					continue
				}

				_, _ = os.Stdout.WriteString("\r\n")
				started, err := conf.InteractCommand(addr, c, ses, sclient, state, shell)
				if err != nil {
					if err == io.EOF {
						conf.Logger.Debugf("%s session closed", addr)
						// If the session closed, shut down the entire client, since few servers work correctly after
						// the first shell/exec is closed
						sclient.Close()
						return
					}
					conf.Logger.Errorf("%s session command failed: %v", addr, err)
				}
				if started && err == nil {
					conf.Logger.Infof("%s session spawned a subprocess", addr)
				}
				os.Stdout.Sync()
				continue
			}

			if ses.Started() {
				if !state.Shell() {
					// Automatically handle local echo in exec mode
					_, _ = os.Stdout.Write(c)
					os.Stdout.Sync()
					continue
				}
				if _, err := shell.Write(c); err != nil {
					conf.Logger.Errorf("%s session write failed: %v", addr, err)
					return
				}
			}
		}
	}
}

// TODO: Investigate support for SIGINFO (INFO@openssh.com)
var sshValidSignals = []string{"ABRT", "ALRM", "FPE", "HUP", "ILL", "INT", "KILL", "PIPE", "QUIT", "SEGV", "TERM", "USR1", "USR2"}

func (conf *ScanConfig) InteractCommand(addr string, data []byte, ses *ssh.Session, sclient *ssh.Client, state *interactSessionState, shell io.WriteCloser) (bool, error) {
	args := strings.Fields(strings.TrimSpace(string(data)))
	if len(args) == 0 {
		return false, fmt.Errorf("empty command")
	}

	waitForReply := false
	if len(args) > 1 && args[0] == "wait" {
		waitForReply = true
		args = args[1:]
	}

	switch strings.ToLower(args[0]) {

	case "wait":
		return false, fmt.Errorf("missing command for wait")

	case ".", "quit", "exit":
		return false, io.EOF

	case "help", "?":
		conf.InteractShowHelp(addr)
		return false, nil

	case "break":
		breakMS := uint32(60)
		if len(args) > 1 {
			v, _ := strconv.ParseUint(args[1], 10, 32)
			breakMS = uint32(v)
		}
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, breakMS)
		ok, err := ses.SendRequest("break", waitForReply, payload)
		if err != nil {
			if err == io.EOF {
				return false, io.EOF
			}
			return false, fmt.Errorf("break failed: %v", err)
		}
		if waitForReply && !ok {
			return false, fmt.Errorf("%s was rejected", args[0])
		}
		return false, nil

	case "req":
		if len(args) < 2 {
			return false, fmt.Errorf("missing request name")
		}
		var payload []byte
		if len(args) > 2 {
			payload = []byte(strings.Join(args[2:], " "))
		}
		ok, err := ses.SendRequest(args[1], waitForReply, payload)
		if err != nil {
			if err == io.EOF {
				return false, io.EOF
			}
			return false, fmt.Errorf("request %s failed: %v", args[1], err)
		}
		if waitForReply && !ok {
			return false, fmt.Errorf("%s was rejected", args[1])
		}
		return false, nil

	case "sub":
		if len(args) < 2 {
			return false, fmt.Errorf("missing subsystem name")
		}

		ok, err := ses.SendRequest("subsystem", waitForReply, nil)
		if err != nil {
			if err == io.EOF {
				return false, io.EOF
			}
			return false, fmt.Errorf("subsystem request %s failed: %v", args[1], err)
		}
		if waitForReply && !ok {
			return false, fmt.Errorf("%s was rejected", args[1])
		}
		return false, nil

	case "shell":
		err := ses.Shell()
		if err == nil {
			state.SetStarted()
			state.SetShell()
		}
		return true, err

	case "exec":
		err := ses.Start(strings.Join(args[1:], " "))
		if err == nil {
			state.SetStarted()
		}
		return true, err

	case "send":
		data := strings.Join(args[1:], " ")
		_, err := shell.Write(processSendBytes(data))
		return false, err

	case "sendb":
		data := processSendBytes(strings.Join(args[1:], " "))
		for i := 0; i < len(data); i++ {
			_, err := shell.Write(data[i : i+1])
			if err != nil {
				return false, err
			}
		}
		return false, nil

	case "pty":
		tmodes := ssh.TerminalModes{
			ssh.ECHO:          1,
			ssh.TTY_OP_ISPEED: 14400,
			ssh.TTY_OP_OSPEED: 14400,
		}
		fd := int(os.Stdin.Fd())
		tw, th, err := term.GetSize(fd)
		if err != nil {
			conf.Logger.Errorf("%s failed to get terminal height and width: %v", addr, err)
			tw = 80
			th = 40
		}

		if waitForReply {
			fmt.Printf("\r\nwaiting for reply...\r\n")
			err = ses.RequestPty("xterm-256color", th, tw, tmodes)
		} else {
			err = ses.RequestPtyNoReply("xterm-256color", th, tw, tmodes)
		}
		if err != nil {
			conf.Logger.Errorf("%s pty request failed: %v", addr, err)
		} else {
			state.SetPty()
		}
		return false, err

	case "env":
		for _, arg := range args[1:] {
			evar, eval, found := strings.Cut(arg, "=")
			if !found || len(eval) == 0 {
				return false, fmt.Errorf("invalid env value: %s", arg)
			}
			var err error
			if waitForReply {
				fmt.Printf("\r\nwaiting for reply...\r\n")
				err = ses.Setenv(evar, eval)
			} else {
				err = ses.SetenvNoReply(evar, eval)
			}
			if err != nil {
				if err == io.EOF {
					return false, io.EOF
				}
				return false, fmt.Errorf("setenv %s=%s failed: %v", evar, eval, err)
			}
		}
		return false, nil

	case "signal":
		if len(args) < 2 {
			return false, fmt.Errorf("missing signal name (%s)", strings.Join(sshValidSignals, " "))
		}
		for _, name := range args[1:] {
			err := ses.Signal(ssh.Signal(args[1]))
			if err != nil {
				if err == io.EOF {
					return false, io.EOF
				}
				return false, fmt.Errorf("signal %s failed: %v", name, err)
			}
		}
		return false, nil

	case "tcp":
		if len(args) < 3 {
			return false, fmt.Errorf("missing destination host and port")
		}
		host := args[1]
		port := args[2]
		go func() {
			defer func() {
				if r := recover(); r != nil {
					conf.Logger.Errorf("tcp connection: %v", r)
				}
			}()
			conf.Logger.Infof("connecting to %s:%s...", host, port)
			c, err := sclient.Dial("tcp", net.JoinHostPort(host, port))
			if err != nil {
				conf.Logger.Errorf("tcp %s:%s failed: %v", host, port, err)
				return
			}
			conf.Logger.Warnf("successfully connected to %s:%s", host, port)
			c.Close()
		}()
		return false, nil

	case "unix":
		if len(args) < 2 {
			return false, fmt.Errorf("missing destination path")
		}
		upath := args[1]
		go func() {
			defer func() {
				if r := recover(); r != nil {
					conf.Logger.Errorf("unix connection: %v", r)
				}
			}()
			conf.Logger.Infof("connecting to unix:%s", upath)
			c, err := sclient.Dial("unix", upath)
			if err != nil {
				conf.Logger.Errorf("connection to unix:%s failed: %v", upath, err)
				return
			}
			conf.Logger.Warnf("successfully connected to unix:%s", upath)
			c.Close()
		}()
		return false, nil
	}

	return false, fmt.Errorf("unknown command: %s", strings.Join(args, " "))
}

var patReplaceHexEscape = regexp.MustCompile(`(\\x[a-fA-F0-9]{2}|\\[rnt])`)

func processSendBytes(s string) []byte {
	s = patReplaceHexEscape.ReplaceAllStringFunc(s, func(h string) string {
		if len(h) == 4 {
			b, _ := hex.DecodeString(h[2:])
			return string(b)
		}
		if len(h) == 2 {
			switch h[1] {
			case 'r':
				return "\r"
			case 'n':
				return "\n"
			case 't':
				return "\t"
			}
		}
		return h
	})
	return []byte(s)
}

type SessionOutputWriter struct {
	output io.Writer
}

func NewSessionOutputWriter(w io.Writer) *SessionOutputWriter {
	return &SessionOutputWriter{
		output: w,
	}
}

func (w *SessionOutputWriter) Write(p []byte) (int, error) {
	buff := []byte{}
	var last byte
	for i, c := range p {
		if i > 0 && c == '\n' && last != '\r' {
			buff = append(buff, '\r')
			buff = append(buff, c)
		} else {
			buff = append(buff, c)
		}
		last = c
	}
	return w.output.Write(buff)
}
