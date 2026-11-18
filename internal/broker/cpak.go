package broker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type CpakRequest struct {
	Operation string `json:"operation"`
	Package   string `json:"package,omitempty"`
	Flatpak   bool   `json:"flatpak,omitempty"`
}

var cpakName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var cpakFlatpakID = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_-]*){2,}$`)

// CpakArguments constructs the host command; the wire protocol never accepts argv.
func CpakArguments(r CpakRequest) ([]string, error) {
	switch r.Operation {
	case "doctor", "list":
		if r.Package == "" && !r.Flatpak {
			return []string{r.Operation}, nil
		}
	case "install", "run", "update", "remove":
		if r.Flatpak {
			if r.Operation == "install" && len(r.Package) <= 255 && cpakFlatpakID.MatchString(r.Package) {
				return []string{"install", "--flatpak", r.Package}, nil
			}
			break
		}
		valid := cpakName.MatchString(r.Package)
		if strings.HasPrefix(r.Package, "https://github.com/") {
			u, err := url.Parse(r.Package)
			if err == nil && u.Host == "github.com" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.RawPath == "" {
				parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
				valid = len(parts) == 2 && cpakName.MatchString(parts[0]) && cpakName.MatchString(parts[1])
			}
		}
		if !valid || (r.Operation == "install" && !strings.HasPrefix(r.Package, "https://github.com/")) {
			break
		}
		args := []string{r.Operation, r.Package}
		if r.Operation == "update" {
			args = append(args, "--non-interactive")
		}
		return args, nil
	}
	return nil, fmt.Errorf("unsupported cpak operation or package")
}

func ParseCpakRequest(args []string) (CpakRequest, error) {
	var r CpakRequest
	if len(args) > 0 {
		r.Operation = args[0]
	}
	switch {
	case len(args) == 1:
	case len(args) == 2:
		r.Package = args[1]
	case len(args) == 3 && args[0] == "install" && args[1] == "--flatpak":
		r.Flatpak, r.Package = true, args[2]
	default:
		return r, fmt.Errorf("supported: cpak doctor|list; cpak install <https://github.com/owner/repo>; cpak install --flatpak <app.id>; cpak run|update|remove <package>")
	}
	_, err := CpakArguments(r)
	return r, err
}

func (s *Server) authorizeCpak(req rpcRequest, peer peerIdentity) ([]string, error) {
	if !peer.isOwner(uint32(os.Getuid())) || parseOrigin(req.Origin).Remote || req.Cpak == nil {
		return nil, fmt.Errorf("cpak: local owner credentials required")
	}
	args, err := CpakArguments(*req.Cpak)
	if err != nil {
		return nil, err
	}
	reason := "Allow this confined process to use cpak on your host account?\n\n" + strings.Join(args, " ") +
		"\n\nThis uses your host applications and data, outside the ush overlay."
	if req.Cpak.Operation == "install" {
		reason += "\nThe package and its dependencies may request access to your files, devices and host services. Only continue if you trust the publisher."
	}
	allowed := s.confirmDialog("cpak host access", reason)
	if s.auditLog != nil {
		decision := "deny"
		if allowed {
			decision = "allow"
		}
		s.auditLog.Write(AuditEntry{Timestamp: time.Now(), Category: "cpak", Resource: strings.Join(args, " "), Decision: decision, Source: "user_dialog", Reason: fmt.Sprintf("peer pid=%d uid=%d", peer.pid, peer.uid)})
	}
	if !allowed {
		return nil, fmt.Errorf("cpak: host access denied")
	}
	return args, nil
}

func cpakCommand(ctx context.Context, args []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/usr/bin/cpak", args...)
	cmd.Dir, _ = os.UserHomeDir()
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	for _, key := range []string{"HOME", "USER", "LOGNAME", "XDG_RUNTIME_DIR", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "DBUS_SESSION_BUS_ADDRESS", "WAYLAND_DISPLAY", "DISPLAY", "XAUTHORITY", "LANG", "LC_ALL", "TMPDIR", "TMP", "TEMP"} {
		if value, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	return cmd
}

func (s *Server) serveCpak(conn net.Conn, req rpcRequest, peer peerIdentity) {
	s.serveCpakCommand(conn, req, peer, cpakCommand)
}

func (s *Server) serveCpakCommand(conn net.Conn, req rpcRequest, peer peerIdentity, command func(context.Context, []string) *exec.Cmd) {
	args, err := s.authorizeCpak(req, peer)
	if err != nil {
		_ = writeMessage(conn, rpcResponse{Error: err.Error()})
		return
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return
	}
	if err = writeMessage(conn, rpcResponse{OK: true}); err != nil {
		return
	}
	files, err := receiveCpakFiles(uc)
	if err != nil {
		_ = writeMessage(conn, rpcResponse{Error: err.Error()})
		return
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Closing the client also cancels the host command, including while it waits for input.
	go func() { var b [1]byte; _, _ = conn.Read(b[:]); cancel() }()
	cmd := command(ctx, args)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = files[0], files[1], files[2]
	code := 0
	if err = cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
			if code < 0 {
				code = 130
			}
		} else {
			_ = writeMessage(conn, rpcResponse{Error: "cpak: host command could not start"})
			return
		}
	}
	_ = writeMessage(conn, struct {
		Code int `json:"code"`
	}{code})
}

func receiveCpakFiles(conn *net.UnixConn) ([]*os.File, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	var data [1]byte
	oob := make([]byte, unix.CmsgSpace(4*4))
	_, n, flags, _, err := conn.ReadMsgUnix(data[:], oob)
	if err != nil {
		return nil, err
	}
	messages, err := unix.ParseSocketControlMessage(oob[:n])
	if err != nil {
		return nil, err
	}
	var files []*os.File
	valid := flags&unix.MSG_CTRUNC == 0
	for _, message := range messages {
		rights, err := unix.ParseUnixRights(&message)
		if err != nil {
			valid = false
			continue
		}
		for _, fd := range rights {
			unix.CloseOnExec(fd)
			files = append(files, os.NewFile(uintptr(fd), "cpak-stdio"))
			var st unix.Stat_t
			if unix.Fstat(fd, &st) != nil || (st.Mode&unix.S_IFMT != unix.S_IFIFO && st.Mode&unix.S_IFMT != unix.S_IFCHR) {
				valid = false
			}
		}
	}
	if !valid || len(files) != 3 {
		for _, f := range files {
			f.Close()
		}
		return nil, fmt.Errorf("cpak: expected terminal or pipe descriptors")
	}
	return files, nil
}

// RunCpak passes only stdio descriptors. Paths, environment and executable stay host-owned.
func (c *Client) RunCpak(ctx context.Context, req CpakRequest, stdin *os.File, stdout, stderr io.Writer) (int, error) {
	if _, err := CpakArguments(req); err != nil {
		return 1, err
	}
	conn, err := net.DialTimeout("unix", c.socket, dialDeadline)
	if err != nil {
		return 1, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(permissionReadDeadline))
	if err = writeMessage(conn, rpcRequest{Method: "Cpak", Cpak: &req, SessionID: c.sessionID, Origin: c.origin}); err != nil {
		return 1, err
	}
	r := bufio.NewReader(conn)
	var reply rpcResponse
	if err = readMessage(r, &reply); err != nil {
		return 1, err
	}
	if reply.Error != "" {
		return 1, fmt.Errorf("%s", reply.Error)
	}
	if !reply.OK {
		return 1, fmt.Errorf("cpak: broker did not authorize the request")
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		return 1, err
	}
	defer outR.Close()
	defer outW.Close()
	errR, errW, err := os.Pipe()
	if err != nil {
		return 1, err
	}
	defer errR.Close()
	defer errW.Close()
	_, _, err = conn.(*net.UnixConn).WriteMsgUnix([]byte{0}, unix.UnixRights(int(stdin.Fd()), int(outW.Fd()), int(errW.Fd())), nil)
	if err != nil {
		return 1, err
	}
	outW.Close()
	errW.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(stdout, outR); done <- struct{}{} }()
	go func() { _, _ = io.Copy(stderr, errR); done <- struct{}{} }()
	_ = conn.SetDeadline(time.Time{})
	var result struct {
		Code  int    `json:"code"`
		Error string `json:"error"`
	}
	err = readMessage(r, &result)
	// An application may keep inherited stdio after cpak exits. Do not wait forever.
	outR.SetReadDeadline(time.Now().Add(time.Second))
	errR.SetReadDeadline(time.Now().Add(time.Second))
	<-done
	<-done
	if err != nil {
		return 1, err
	}
	if result.Error != "" {
		return 1, fmt.Errorf("%s", result.Error)
	}
	return result.Code, nil
}
