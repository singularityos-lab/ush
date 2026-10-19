// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// readline.go implements interactive line editing for the ush shell
// using golang.org/x/term to handle terminal raw mode.
package shell

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

// CompletionFunc is the completion function.
// It receives the current line and cursor position.
// Returns: head (before the match), completions, tail (after the cursor).
type CompletionFunc func(line string, pos int) (head string, completions []string, tail string)

// Readline manages interactive input with history and tab-completion.
type Readline struct {
	histFile   string
	history    []string
	histIdx    int
	completion CompletionFunc
	state      *term.State
	// lastCursorRow is the physical row offset of the cursor below the
	// prompt's starting row after the last redraw. Used to reposition the
	// cursor before clearing on the next redraw so that wrapped lines are
	// erased instead of being left behind.
	lastCursorRow int
	pending       []byte
	kill          []rune
}

// newReadline creates a new Readline instance.
func newReadline(histFile string, completion CompletionFunc) (*Readline, error) {
	rl := &Readline{
		histFile:   histFile,
		completion: completion,
	}
	rl.loadHistory()
	rl.histIdx = len(rl.history)
	return rl, nil
}

// Close restores the terminal state.
func (rl *Readline) Close() {
	if rl.state != nil {
		term.Restore(int(os.Stdin.Fd()), rl.state)
	}
}

// Readline reads a line with the given prompt.
// Supports the common bash/readline bindings:
//   - Up/Down, Ctrl+P/N for history, Alt+< and Alt+> for its ends
//   - Ctrl+R/Ctrl+S for incremental history search
//   - Tab for completion, extending the common prefix of several matches
//   - Ctrl+A/E, Home/End, Ctrl+B/F, Alt+B/F and Ctrl+Left/Right for moving
//   - Ctrl+K/U/W, Alt+D, Alt+Backspace to kill and Ctrl+Y to yank back
//   - Ctrl+T to transpose, Alt+. for the last argument of the previous line
//   - Ctrl+L to clear the screen, Ctrl+C to interrupt, Ctrl+D for EOF
func (rl *Readline) Readline(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())

	if !term.IsTerminal(fd) {
		return rl.readLineSimple(prompt)
	}
	state, err := term.MakeRaw(fd)
	if err != nil {
		return rl.readLineSimple(prompt)
	}
	rl.state = state
	defer func() {
		term.Restore(fd, state)
		rl.state = nil
	}()

	fmt.Fprint(os.Stdout, prompt)
	rl.lastCursorRow = 0

	e := &lineEditor{rl: rl, prompt: prompt, histIdx: len(rl.history)}
	for {
		b, err := rl.readKey()
		if err != nil {
			if err == io.EOF && len(e.buf) == 0 {
				fmt.Fprint(os.Stdout, "\r\n")
				return "", io.EOF
			}
			return string(e.buf), err
		}
		if done, line, err := e.handle(b); done {
			return line, err
		}
	}
}

func (rl *Readline) readKey() ([]byte, error) {
	chunk := make([]byte, 256)
	for {
		if key, rest, ok := nextKey(rl.pending); ok {
			rl.pending = rest
			return key, nil
		}
		n, err := os.Stdin.Read(chunk)
		if n > 0 {
			rl.pending = append(rl.pending, chunk[:n]...)
			continue
		}
		if len(rl.pending) > 0 {
			key := rl.pending
			rl.pending = nil
			return key, nil
		}
		if err == nil {
			err = io.EOF
		}
		return nil, err
	}
}

type lineEditor struct {
	rl      *Readline
	prompt  string
	buf     []rune
	pos     int
	histIdx int
	saved   string

	searching   bool
	searchBack  bool
	query       []rune
	lastQuery   []rune
	matchIdx    int
	failed      bool
	searchStart []rune
	searchPos   int

	lastArgIdx int
	lastKey    string
}

func (e *lineEditor) redraw() {
	if e.searching {
		label := "reverse-i-search"
		if !e.searchBack {
			label = "i-search"
		}
		if e.failed {
			label = "failed " + label
		}
		e.rl.redrawLine("("+label+")`"+string(e.query)+"': ", e.buf, e.pos)
		return
	}
	e.rl.redrawLine(e.prompt, e.buf, e.pos)
}

func (e *lineEditor) insert(rs []rune) {
	e.buf = append(e.buf[:e.pos], append(append([]rune{}, rs...), e.buf[e.pos:]...)...)
	e.pos += len(rs)
}

func (e *lineEditor) kill(from, to int) {
	if from >= to {
		return
	}
	e.rl.kill = append([]rune{}, e.buf[from:to]...)
	e.buf = append(e.buf[:from], e.buf[to:]...)
	e.pos = from
}

func (e *lineEditor) setLine(s string) {
	e.buf = []rune(s)
	e.pos = len(e.buf)
}

func (e *lineEditor) gotoHistory(idx int) {
	if idx < 0 || idx > len(e.rl.history) || idx == e.histIdx {
		return
	}
	if e.histIdx == len(e.rl.history) {
		e.saved = string(e.buf)
	}
	e.histIdx = idx
	if idx == len(e.rl.history) {
		e.setLine(e.saved)
	} else {
		e.setLine(e.rl.history[idx])
	}
}

func isWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

func (e *lineEditor) wordLeft() int {
	p := e.pos
	for p > 0 && !isWordRune(e.buf[p-1]) {
		p--
	}
	for p > 0 && isWordRune(e.buf[p-1]) {
		p--
	}
	return p
}

func (e *lineEditor) wordRight() int {
	p := e.pos
	for p < len(e.buf) && !isWordRune(e.buf[p]) {
		p++
	}
	for p < len(e.buf) && isWordRune(e.buf[p]) {
		p++
	}
	return p
}

func (e *lineEditor) handle(b []byte) (bool, string, error) {
	k := keyName(b)
	if e.searching {
		if e.handleSearch(k, b) {
			return false, "", nil
		}
		if k == "esc" {
			return false, "", nil
		}
	}
	defer func() { e.lastKey = k }()

	switch k {
	case "enter":
		fmt.Fprint(os.Stdout, "\r\n")
		line := string(e.buf)
		if line != "" {
			e.rl.addHistory(line)
		}
		return true, line, nil
	case "ctrl-c":
		fmt.Fprint(os.Stdout, "\r\n")
		return true, "", &interruptError{}
	case "ctrl-d":
		if len(e.buf) == 0 {
			fmt.Fprint(os.Stdout, "\r\n")
			return true, "", io.EOF
		}
		if e.pos < len(e.buf) {
			e.buf = append(e.buf[:e.pos], e.buf[e.pos+1:]...)
		}
	case "delete":
		if e.pos < len(e.buf) {
			e.buf = append(e.buf[:e.pos], e.buf[e.pos+1:]...)
		}
	case "home", "ctrl-a":
		e.pos = 0
	case "end", "ctrl-e":
		e.pos = len(e.buf)
	case "left", "ctrl-b":
		if e.pos > 0 {
			e.pos--
		}
	case "right", "ctrl-f":
		if e.pos < len(e.buf) {
			e.pos++
		}
	case "word-left", "alt-b":
		e.pos = e.wordLeft()
	case "word-right", "alt-f":
		e.pos = e.wordRight()
	case "up", "ctrl-p":
		e.gotoHistory(e.histIdx - 1)
	case "down", "ctrl-n":
		e.gotoHistory(e.histIdx + 1)
	case "alt-<":
		e.gotoHistory(0)
	case "alt->":
		e.gotoHistory(len(e.rl.history))
	case "ctrl-l":
		fmt.Fprint(os.Stdout, "\033[2J\033[H")
		e.rl.lastCursorRow = 0
	case "ctrl-k":
		e.kill(e.pos, len(e.buf))
	case "ctrl-u":
		e.kill(0, e.pos)
	case "ctrl-w":
		p := e.pos
		for p > 0 && unicode.IsSpace(e.buf[p-1]) {
			p--
		}
		for p > 0 && !unicode.IsSpace(e.buf[p-1]) {
			p--
		}
		e.kill(p, e.pos)
	case "alt-backspace":
		e.kill(e.wordLeft(), e.pos)
	case "alt-d":
		end := e.wordRight()
		start := e.pos
		e.kill(start, end)
	case "ctrl-y":
		e.insert(e.rl.kill)
	case "ctrl-t":
		if len(e.buf) >= 2 && e.pos > 0 {
			p := e.pos
			if p == len(e.buf) {
				p--
			}
			e.buf[p-1], e.buf[p] = e.buf[p], e.buf[p-1]
			e.pos = p + 1
		}
	case "alt-.":
		e.yankLastArg()
	case "backspace":
		if e.pos > 0 {
			e.buf = append(e.buf[:e.pos-1], e.buf[e.pos:]...)
			e.pos--
		}
	case "tab":
		e.complete()
	case "ctrl-r", "ctrl-s":
		e.startSearch(k == "ctrl-r")
	case "text":
		for _, ch := range string(b) {
			if ch >= 32 {
				e.insert([]rune{ch})
			}
		}
	default:
		return false, "", nil
	}
	e.redraw()
	return false, "", nil
}

func (e *lineEditor) yankLastArg() {
	if e.lastKey != "alt-." {
		e.lastArgIdx = len(e.rl.history)
	} else if e.lastArgIdx < len(e.rl.history) {
		prev := lastWord(e.rl.history[e.lastArgIdx])
		e.pos -= len([]rune(prev))
		e.buf = append(e.buf[:e.pos], e.buf[e.pos+len([]rune(prev)):]...)
	}
	for e.lastArgIdx > 0 {
		e.lastArgIdx--
		if w := lastWord(e.rl.history[e.lastArgIdx]); w != "" {
			e.insert([]rune(w))
			return
		}
	}
}

func (e *lineEditor) complete() {
	if e.rl.completion == nil {
		return
	}
	line := string(e.buf)
	cursor := len(string(e.buf[:e.pos]))
	head, completions, tail := e.rl.completion(line, cursor)
	seen := map[string]bool{}
	var uniq []string
	for _, c := range completions {
		if !seen[c] {
			seen[c] = true
			uniq = append(uniq, c)
		}
	}
	switch {
	case len(uniq) == 1:
		e.buf = []rune(head + uniq[0] + tail)
		e.pos = len([]rune(head + uniq[0]))
	case len(uniq) > 1:
		common := commonPrefix(uniq)
		typed := ""
		if len(head) <= cursor {
			typed = line[len(head):cursor]
		}
		if len(common) > len(typed) && strings.HasPrefix(common, typed) {
			e.buf = []rune(head + common + tail)
			e.pos = len([]rune(head + common))
			return
		}
		fmt.Fprint(os.Stdout, "\r\n")
		fmt.Fprint(os.Stdout, strings.Join(uniq, "  ")+"\r\n")
		e.rl.lastCursorRow = 0
	}
}

func commonPrefix(items []string) string {
	p := items[0]
	for _, s := range items[1:] {
		for !strings.HasPrefix(s, p) {
			_, size := utf8.DecodeLastRuneInString(p)
			p = p[:len(p)-size]
		}
	}
	return p
}

func (e *lineEditor) startSearch(back bool) {
	e.searching = true
	e.searchBack = back
	e.query = nil
	e.failed = false
	e.matchIdx = len(e.rl.history)
	e.searchStart = append([]rune{}, e.buf...)
	e.searchPos = e.pos
}

func (e *lineEditor) find(from int, back bool) bool {
	q := string(e.query)
	for i := from; i >= 0 && i < len(e.rl.history); {
		if j := strings.LastIndex(e.rl.history[i], q); j >= 0 {
			e.matchIdx = i
			e.buf = []rune(e.rl.history[i])
			e.pos = len([]rune(e.rl.history[i][:j]))
			e.histIdx = i
			return true
		}
		if back {
			i--
		} else {
			i++
		}
	}
	return false
}

func (e *lineEditor) research(from int) {
	if len(e.query) == 0 {
		e.failed = false
		return
	}
	e.failed = !e.find(from, e.searchBack)
}

func (e *lineEditor) handleSearch(k string, b []byte) bool {
	switch k {
	case "ctrl-r", "ctrl-s":
		back := k == "ctrl-r"
		if len(e.query) == 0 && len(e.lastQuery) > 0 {
			e.query = append([]rune{}, e.lastQuery...)
			e.searchBack = back
			e.research(e.matchIdx - 1)
			if !back {
				e.research(e.matchIdx + 1)
			}
		} else {
			e.searchBack = back
			if back {
				e.research(e.matchIdx - 1)
			} else {
				e.research(e.matchIdx + 1)
			}
		}
	case "text":
		for _, ch := range string(b) {
			if ch < 32 {
				continue
			}
			e.query = append(e.query, ch)
			from := e.matchIdx
			if from >= len(e.rl.history) {
				from = len(e.rl.history) - 1
			}
			e.research(from)
		}
	case "backspace":
		if len(e.query) > 0 {
			e.query = e.query[:len(e.query)-1]
		}
		e.matchIdx = len(e.rl.history)
		if len(e.query) == 0 {
			e.buf = append([]rune{}, e.searchStart...)
			e.pos = e.searchPos
			e.failed = false
		} else {
			e.research(len(e.rl.history) - 1)
		}
	case "ctrl-g", "ctrl-c":
		e.searching = false
		e.buf = e.searchStart
		e.pos = e.searchPos
		e.histIdx = len(e.rl.history)
	default:
		e.searching = false
		if len(e.query) > 0 {
			e.lastQuery = append([]rune{}, e.query...)
		}
		e.redraw()
		return false
	}
	e.redraw()
	return true
}

func keyName(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	c := b[0]
	switch {
	case c == '\r' || c == '\n':
		return "enter"
	case c == 9:
		return "tab"
	case c == 127 || c == 8:
		return "backspace"
	case c == 27:
		return escName(b)
	case c < 32:
		return "ctrl-" + string(rune('a'+c-1))
	}
	return "text"
}

func escName(b []byte) string {
	if len(b) == 1 {
		return "esc"
	}
	if b[1] == 'O' && len(b) == 3 {
		switch b[2] {
		case 'A':
			return "up"
		case 'B':
			return "down"
		case 'C':
			return "right"
		case 'D':
			return "left"
		case 'H':
			return "home"
		case 'F':
			return "end"
		}
		return ""
	}
	if b[1] != '[' {
		if len(b) == 2 {
			switch b[1] {
			case 127, 8:
				return "alt-backspace"
			}
			if b[1] >= 32 && b[1] < 127 {
				return "alt-" + string(rune(b[1]))
			}
		}
		return ""
	}
	params, final := string(b[2:len(b)-1]), b[len(b)-1]
	mod := ""
	if i := strings.IndexByte(params, ';'); i >= 0 {
		mod = params[i+1:]
	}
	word := mod == "5" || mod == "3"
	switch final {
	case 'A':
		return "up"
	case 'B':
		return "down"
	case 'C':
		if word {
			return "word-right"
		}
		return "right"
	case 'D':
		if word {
			return "word-left"
		}
		return "left"
	case 'H':
		return "home"
	case 'F':
		return "end"
	case '~':
		switch params {
		case "1", "7":
			return "home"
		case "4", "8":
			return "end"
		case "3":
			return "delete"
		}
	}
	return ""
}

func nextKey(p []byte) (key, rest []byte, ok bool) {
	if len(p) == 0 {
		return nil, p, false
	}
	if p[0] == 27 {
		if len(p) == 1 {
			return p[:1], p[1:], true
		}
		switch {
		case p[1] == '[':
			for i := 2; i < len(p); i++ {
				if p[i] >= 0x40 && p[i] <= 0x7e {
					return p[:i+1], p[i+1:], true
				}
			}
			return nil, p, false
		case p[1] == 'O':
			if len(p) < 3 {
				return nil, p, false
			}
			return p[:3], p[3:], true
		case p[1] >= 32 && p[1] <= 127, p[1] == 8:
			return p[:2], p[2:], true
		}
		return p[:1], p[1:], true
	}
	if p[0] < 32 || p[0] == 127 {
		return p[:1], p[1:], true
	}
	i := 0
	for i < len(p) && p[i] >= 32 && p[i] != 127 {
		if !utf8.FullRune(p[i:]) {
			break
		}
		_, size := utf8.DecodeRune(p[i:])
		i += size
	}
	if i == 0 {
		return nil, p, false
	}
	return p[:i], p[i:], true
}

// redrawLine redraws the current line, accounting for wrapping when the
// rendered prompt+buffer is wider than the terminal.
func (rl *Readline) redrawLine(prompt string, buf []rune, pos int) {
	cols, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || cols <= 0 {
		cols = 80
	}

	// Move the cursor back up to the prompt's starting row, then clear
	// everything below so wrapped remnants disappear.
	if rl.lastCursorRow > 0 {
		fmt.Fprintf(os.Stdout, "\033[%dA", rl.lastCursorRow)
	}
	fmt.Fprint(os.Stdout, "\r\033[J")

	fmt.Fprint(os.Stdout, prompt)
	fmt.Fprint(os.Stdout, string(buf))

	promptLen := visibleLen(prompt)
	endTotal := promptLen + runesWidth(buf)
	cursorTotal := promptLen + runesWidth(buf[:pos])

	endRow := 0
	if cols > 0 {
		endRow = endTotal / cols
	}
	cursorRow := 0
	cursorCol := cursorTotal
	if cols > 0 {
		cursorRow = cursorTotal / cols
		cursorCol = cursorTotal % cols
	}

	// If the buffer ends exactly at a column boundary the terminal hasn't
	// yet moved to the next row; force it so subsequent input lands on the
	// fresh row instead of overwriting the last column.
	if endTotal > 0 && cols > 0 && endTotal%cols == 0 {
		fmt.Fprint(os.Stdout, "\r\n")
		endRow++
	}

	// Move cursor from end-of-output up to the target row and column.
	if endRow > cursorRow {
		fmt.Fprintf(os.Stdout, "\033[%dA", endRow-cursorRow)
	}
	fmt.Fprint(os.Stdout, "\r")
	if cursorCol > 0 {
		fmt.Fprintf(os.Stdout, "\033[%dC", cursorCol)
	}

	rl.lastCursorRow = cursorRow
}

// visibleLen returns the number of visible cells in s, ignoring ANSI escape
// sequences such as SGR color codes.
func visibleLen(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		if inEsc {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEsc = false
			}
			continue
		}
		if r == '\x1b' {
			inEsc = true
			continue
		}
		n += runeWidth(r)
	}
	return n
}

func runesWidth(rs []rune) int {
	n := 0
	for _, r := range rs {
		n += runeWidth(r)
	}
	return n
}

func runeWidth(r rune) int {
	switch {
	case r == 0x200d, r >= 0xfe00 && r <= 0xfe0f, unicode.Is(unicode.Mn, r), unicode.Is(unicode.Me, r):
		return 0
	case r >= 0x1100 && r <= 0x115f,
		r >= 0x2e80 && r <= 0xa4cf,
		r >= 0xac00 && r <= 0xd7a3,
		r >= 0xf900 && r <= 0xfaff,
		r >= 0xfe30 && r <= 0xfe4f,
		r >= 0xff00 && r <= 0xff60,
		r >= 0xffe0 && r <= 0xffe6,
		r >= 0x1f300 && r <= 0x1f64f,
		r >= 0x1f680 && r <= 0x1f6ff,
		r >= 0x1f900 && r <= 0x1faff,
		r >= 0x20000 && r <= 0x3fffd:
		return 2
	}
	return 1
}

// moveCursor moves the cursor without redrawing.
func (rl *Readline) moveCursor(prompt string, buf []rune, pos int) {
	rl.redrawLine(prompt, buf, pos)
}

// readLineSimple reads a simple line (non-interactive).
func (rl *Readline) readLineSimple(prompt string) (string, error) {
	fmt.Fprint(os.Stdout, prompt)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return scanner.Text(), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", io.EOF
}

const maxHistory = 5000

// addHistory adds an entry to history (deduplicating consecutive entries)
// and appends it to the history file right away, so a closed terminal or a
// second shell does not lose it.
func (rl *Readline) addHistory(line string) {
	if len(rl.history) > 0 && rl.history[len(rl.history)-1] == line {
		return
	}
	rl.history = append(rl.history, line)
	if len(rl.history) > maxHistory {
		rl.history = rl.history[len(rl.history)-maxHistory:]
	}
	rl.histIdx = len(rl.history)
	if rl.histFile == "" || strings.Contains(line, "\n") {
		return
	}
	if err := os.MkdirAll(filepath.Dir(rl.histFile), 0700); err != nil {
		return
	}
	f, err := os.OpenFile(rl.histFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return
	}
	f.WriteString(line + "\n")
	f.Close()
}

// loadHistory loads history from the file, trimming it when it grew past
// maxHistory entries.
func (rl *Readline) loadHistory() {
	data, err := os.ReadFile(rl.histFile)
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(data), "\n") {
		if l != "" {
			rl.history = append(rl.history, l)
		}
	}
	if len(rl.history) > maxHistory {
		rl.history = rl.history[len(rl.history)-maxHistory:]
		os.WriteFile(rl.histFile, []byte(strings.Join(rl.history, "\n")+"\n"), 0600)
	}
}

type interruptError struct{}

func (e *interruptError) Error() string { return "interrupt" }
