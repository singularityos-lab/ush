package security

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	DeleteGuardLimit  = 200
	DeleteGuardWindow = 10 * time.Second
)

var personalDirs = []string{"Desktop", "Documents", "Downloads", "Music", "Pictures", "Public", "Templates", "Videos"}

var deleteExemptNames = map[string]bool{
	"tmp": true, ".tmp": true, ".cache": true, "node_modules": true, "build": true,
	"target": true, "dist": true, "__pycache__": true, ".git": true, ".venv": true,
	"venv": true, ".tox": true, ".gradle": true, "_build": true, ".zig-cache": true,
	"zig-cache": true, "zig-out": true,
}

type DeleteGuard struct {
	home      string
	roots     []string
	exempt    []string
	protected map[string]bool
	limit     int
	window    time.Duration
	confirm   func(cmd, where string, count int) bool
	shellPid  func() int

	mu     sync.Mutex
	hits   []deleteHit
	jobs   map[jobKey]*jobState
	strict time.Time
}

type deleteHit struct {
	at  time.Time
	job jobKey
}

type jobKey struct {
	pid   int
	start uint64
}

type jobState struct {
	done  chan struct{}
	allow bool
	until time.Time
}

func NewDeleteGuard(home string, shares []string) *DeleteGuard {
	home = filepath.Clean(home)
	g := &DeleteGuard{
		home:      home,
		roots:     []string{home},
		exempt:    []string{filepath.Join(home, ".local", "share", "ush")},
		protected: map[string]bool{home: true},
		limit:     DeleteGuardLimit,
		window:    DeleteGuardWindow,
		jobs:      make(map[jobKey]*jobState),
	}
	for _, d := range append(personalDirs, userDirNames(home)...) {
		g.protected[filepath.Join(home, d)] = true
	}
	for _, s := range shares {
		s = filepath.Clean(s)
		if s == "/" || s == "" {
			continue
		}
		g.roots = append(g.roots, s)
		g.protected[s] = true
	}
	return g
}

func (g *DeleteGuard) SetConfirm(fn func(cmd, where string, count int) bool) { g.confirm = fn }

func (g *DeleteGuard) SetShellPid(fn func() int) { g.shellPid = fn }

func (g *DeleteGuard) SetLimit(limit int, window time.Duration) {
	g.limit, g.window = limit, window
}

func userDirNames(home string) []string {
	f, err := os.Open(filepath.Join(home, ".config", "user-dirs.dirs"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "XDG_") {
			continue
		}
		_, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		v = strings.TrimPrefix(v, "$HOME/")
		if v == "" || v == "$HOME" || strings.Contains(v, "/") {
			continue
		}
		out = append(out, v)
	}
	return out
}

func (g *DeleteGuard) IsProtected(path string) bool {
	p := normHome(filepath.Clean(path))
	for q := range g.protected {
		if normHome(q) == p {
			return true
		}
	}
	return false
}

func (g *DeleteGuard) counted(path string) bool {
	if pathHasPrefix(path, g.exempt) {
		return false
	}
	root := ""
	for _, r := range g.roots {
		if pathHasPrefix(path, []string{r}) && len(r) > len(root) {
			root = r
		}
	}
	if root == "" {
		return false
	}
	rel, err := filepath.Rel(normHome(root), normHome(path))
	if err != nil {
		return false
	}
	for _, part := range strings.Split(rel, "/") {
		if deleteExemptNames[part] {
			return false
		}
	}
	return true
}

func (g *DeleteGuard) where(path string) string {
	dir := filepath.Dir(path)
	if rel, err := filepath.Rel(g.home, dir); err == nil && !strings.HasPrefix(rel, "..") {
		if rel == "." {
			return "~"
		}
		top, _, _ := strings.Cut(rel, "/")
		return "~/" + top
	}
	return dir
}

func (g *DeleteGuard) CheckDelete(pid int, path string) syscall.Errno {
	path = filepath.Clean(path)
	if g.IsProtected(path) {
		return syscall.EPERM
	}
	if !g.counted(path) {
		return 0
	}
	job := g.jobOf(pid)
	now := time.Now()

	g.mu.Lock()
	if st := g.jobs[job]; st != nil {
		g.mu.Unlock()
		<-st.done
		if st.until.IsZero() || now.Before(st.until) {
			if st.allow {
				return 0
			}
			return syscall.EPERM
		}
		g.mu.Lock()
		if g.jobs[job] == st {
			delete(g.jobs, job)
		}
	}
	g.hits = append(g.hits, deleteHit{at: now, job: job})
	cut := 0
	for cut < len(g.hits) && now.Sub(g.hits[cut].at) > g.window {
		cut++
	}
	g.hits = g.hits[cut:]
	if len(g.hits) <= g.limit && now.After(g.strict) {
		g.mu.Unlock()
		return 0
	}
	st := &jobState{done: make(chan struct{})}
	g.jobs[job] = st
	count := len(g.hits)
	g.mu.Unlock()

	allow := false
	if g.confirm != nil {
		allow = g.confirm(processName(job.pid), g.where(path), count)
	}

	g.mu.Lock()
	st.allow = allow
	kept := g.hits[:0]
	for _, h := range g.hits {
		if h.job != job {
			kept = append(kept, h)
		}
	}
	g.hits = kept
	if !allow {
		g.strict = time.Now().Add(2 * time.Minute)
		if g.isShell(job.pid) {
			st.until = g.strict
		}
	}
	g.pruneJobs()
	g.mu.Unlock()
	close(st.done)

	if allow {
		return 0
	}
	if !g.isShell(job.pid) {
		killTree(job.pid)
	}
	return syscall.EPERM
}

func (g *DeleteGuard) CheckRename(pid int, from, to string) syscall.Errno {
	from, to = filepath.Clean(from), filepath.Clean(to)
	if g.IsProtected(from) || g.IsProtected(to) {
		return syscall.EPERM
	}
	if g.counted(from) && !pathHasPrefix(to, g.roots) {
		return g.CheckDelete(pid, from)
	}
	return 0
}

func (g *DeleteGuard) pruneJobs() {
	for k, st := range g.jobs {
		select {
		case <-st.done:
		default:
			continue
		}
		if procStart(k.pid) != k.start {
			delete(g.jobs, k)
		}
	}
}

func (g *DeleteGuard) isShell(pid int) bool {
	return g.shellPid != nil && pid == g.shellPid()
}

func (g *DeleteGuard) jobOf(pid int) jobKey {
	cur := procTgid(pid)
	shell := 0
	if g.shellPid != nil {
		shell = g.shellPid()
	}
	for i := 0; i < 64 && cur != shell; i++ {
		pp := procPpid(cur)
		if pp <= 1 || pp == shell || pp == os.Getpid() {
			break
		}
		cur = pp
	}
	return jobKey{pid: cur, start: procStart(cur)}
}

func processName(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "A program"
	}
	return strings.TrimSpace(string(b))
}

func procStatus(pid int, key string) int {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), key+":"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}

func procTgid(pid int) int {
	if t := procStatus(pid, "Tgid"); t > 0 {
		return t
	}
	return pid
}

func procPpid(pid int) int { return procStatus(pid, "PPid") }

func procStatFields(pid int) []string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return nil
	}
	return strings.Fields(s[i+1:])
}

func procStart(pid int) uint64 {
	f := procStatFields(pid)
	if len(f) < 20 {
		return 0
	}
	v, _ := strconv.ParseUint(f[19], 10, 64)
	return v
}

func killTree(root int) {
	if root <= 1 || root == os.Getpid() {
		return
	}
	children := map[int][]int{}
	if ents, err := os.ReadDir("/proc"); err == nil {
		for _, e := range ents {
			pid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			if f := procStatFields(pid); len(f) > 1 {
				pp, _ := strconv.Atoi(f[1])
				children[pp] = append(children[pp], pid)
			}
		}
	}
	queue := []int{root}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		_ = syscall.Kill(p, syscall.SIGKILL)
		queue = append(queue, children[p]...)
	}
}

// EnterDeleteGuard confines the calling process to the deletion guard filter and
// hands the notification fd to the supervisor over the unix socket sock. Call it
// from the thread that will exec the guarded program.
func EnterDeleteGuard(sock int) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("security: no_new_privs: %w", err)
	}
	fd, err := InstallDeleteGuardFilter()
	if err != nil {
		return err
	}
	err = unix.Sendmsg(sock, []byte{0}, unix.UnixRights(fd), nil, 0)
	unix.Close(fd)
	unix.Close(sock)
	return err
}

// ReceiveFd reads one file descriptor sent with SCM_RIGHTS on sock.
func ReceiveFd(sock int) (int, error) {
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	_, oobn, _, _, err := unix.Recvmsg(sock, buf, oob, unix.MSG_CMSG_CLOEXEC)
	if err != nil {
		return -1, err
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		return -1, fmt.Errorf("security: no fd received")
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) == 0 {
		return -1, fmt.Errorf("security: no fd received")
	}
	return fds[0], nil
}
