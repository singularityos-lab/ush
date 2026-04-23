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
	"strings"
	"unicode"

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
	rl.saveHistory()
}

// Readline reads a line with the given prompt.
// Supports:
//   - Up/Down arrows for history
//   - Ctrl+R for history search
//   - Tab for completion
//   - Ctrl+A/E for beginning/end of line
//   - Ctrl+L to clear the screen
//   - Ctrl+C for interrupt (returns error)
//   - Ctrl+D on empty line for EOF
func (rl *Readline) Readline(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())

	// Enable raw mode only if stdin is a terminal.
	if term.IsTerminal(fd) {
		state, err := term.MakeRaw(fd)
		if err != nil {
			// Fallback: simple line read.
			return rl.readLineSimple(prompt)
		}
		rl.state = state
		defer func() {
			term.Restore(fd, state)
			rl.state = nil
		}()
	} else {
		return rl.readLineSimple(prompt)
	}

	fmt.Fprint(os.Stdout, prompt)
	rl.lastCursorRow = 0

	var buf []rune
	var pos int
	histIdx := len(rl.history)
	savedLine := ""

	for {
		b := make([]byte, 4)
		n, err := os.Stdin.Read(b)
		if err != nil {
			if err == io.EOF && len(buf) == 0 {
				fmt.Fprintln(os.Stdout)
				return "", io.EOF
			}
			return string(buf), err
		}
		b = b[:n]

		switch {
		// Enter
		case b[0] == '\r' || b[0] == '\n':
			fmt.Fprintln(os.Stdout)
			line := string(buf)
			if line != "" {
				rl.addHistory(line)
			}
			return line, nil

		// Ctrl+C
		case b[0] == 3:
			fmt.Fprintln(os.Stdout)
			buf = buf[:0]
			pos = 0
			return "", &interruptError{}

		// Ctrl+D on empty line
		case b[0] == 4:
			if len(buf) == 0 {
				fmt.Fprintln(os.Stdout)
				return "", io.EOF
			}
			// Delete current character.
			if pos < len(buf) {
				buf = append(buf[:pos], buf[pos+1:]...)
				rl.redrawLine(prompt, buf, pos)
			}

		// Ctrl+A (beginning of line)
		case b[0] == 1:
			pos = 0
			rl.moveCursor(prompt, buf, pos)

		// Ctrl+E (end of line)
		case b[0] == 5:
			pos = len(buf)
			rl.moveCursor(prompt, buf, pos)

		// Ctrl+L (clear screen)
		case b[0] == 12:
			fmt.Fprint(os.Stdout, "\033[2J\033[H")
			rl.redrawLine(prompt, buf, pos)

		// Ctrl+K (delete to end of line)
		case b[0] == 11:
			buf = buf[:pos]
			rl.redrawLine(prompt, buf, pos)

		// Ctrl+U (delete from beginning to cursor)
		case b[0] == 21:
			buf = buf[pos:]
			pos = 0
			rl.redrawLine(prompt, buf, pos)

		// Ctrl+W (delete previous word)
		case b[0] == 23:
			if pos > 0 {
				end := pos
				for pos > 0 && unicode.IsSpace(buf[pos-1]) {
					pos--
				}
				for pos > 0 && !unicode.IsSpace(buf[pos-1]) {
					pos--
				}
				buf = append(buf[:pos], buf[end:]...)
				rl.redrawLine(prompt, buf, pos)
			}

		// Tab (completion)
		case b[0] == 9:
			if rl.completion != nil {
				line := string(buf[:pos])
				head, completions, tail := rl.completion(line, pos)
				if len(completions) == 1 {
					newLine := head + completions[0] + tail
					buf = []rune(newLine)
					pos = len([]rune(head + completions[0]))
					rl.redrawLine(prompt, buf, pos)
				} else if len(completions) > 1 {
					fmt.Fprintln(os.Stdout)
					fmt.Fprintln(os.Stdout, strings.Join(completions, "  "))
					rl.redrawLine(prompt, buf, pos)
				}
			}

		// Backspace
		case b[0] == 127 || b[0] == 8:
			if pos > 0 {
				buf = append(buf[:pos-1], buf[pos:]...)
				pos--
				rl.redrawLine(prompt, buf, pos)
			}

		// Escape sequences (arrows, etc.)
		case b[0] == 27 && n >= 3 && b[1] == '[':
			switch b[2] {
			case 'A': // Up - previous history
				if histIdx > 0 {
					if histIdx == len(rl.history) {
						savedLine = string(buf)
					}
					histIdx--
					buf = []rune(rl.history[histIdx])
					pos = len(buf)
					rl.redrawLine(prompt, buf, pos)
				}
			case 'B': // Down - next history
				if histIdx < len(rl.history) {
					histIdx++
					if histIdx == len(rl.history) {
						buf = []rune(savedLine)
					} else {
						buf = []rune(rl.history[histIdx])
					}
					pos = len(buf)
					rl.redrawLine(prompt, buf, pos)
				}
			case 'C': // Right
				if pos < len(buf) {
					pos++
					rl.moveCursor(prompt, buf, pos)
				}
			case 'D': // Left
				if pos > 0 {
					pos--
					rl.moveCursor(prompt, buf, pos)
				}
			case 'H': // Home
				pos = 0
				rl.moveCursor(prompt, buf, pos)
			case 'F': // End
				pos = len(buf)
				rl.moveCursor(prompt, buf, pos)
			case '3': // Delete (ESC [ 3 ~)
				if n >= 4 && b[3] == '~' && pos < len(buf) {
					buf = append(buf[:pos], buf[pos+1:]...)
					rl.redrawLine(prompt, buf, pos)
				}
			}

		// Normal printable characters
		default:
			r := []rune(string(b[:n]))
			for _, ch := range r {
				if ch >= 32 {
					buf = append(buf[:pos], append([]rune{ch}, buf[pos:]...)...)
					pos++
				}
			}
			rl.redrawLine(prompt, buf, pos)
		}
	}
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
	endTotal := promptLen + len(buf)
	cursorTotal := promptLen + pos

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
		n++
	}
	return n
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

// addHistory adds an entry to history (deduplicating consecutive entries).
func (rl *Readline) addHistory(line string) {
	if len(rl.history) > 0 && rl.history[len(rl.history)-1] == line {
		return
	}
	rl.history = append(rl.history, line)
	// Keep at most 5000 entries.
	if len(rl.history) > 5000 {
		rl.history = rl.history[len(rl.history)-5000:]
	}
	rl.histIdx = len(rl.history)
}

// loadHistory loads history from the file.
func (rl *Readline) loadHistory() {
	data, err := os.ReadFile(rl.histFile)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, l := range lines {
		if l != "" {
			rl.history = append(rl.history, l)
		}
	}
}

// saveHistory saves history to the file.
func (rl *Readline) saveHistory() {
	os.MkdirAll(strings.TrimSuffix(rl.histFile, "/"+strings.Split(rl.histFile, "/")[len(strings.Split(rl.histFile, "/"))-1]), 0700)
	os.WriteFile(rl.histFile, []byte(strings.Join(rl.history, "\n")+"\n"), 0600)
}

type interruptError struct{}

func (e *interruptError) Error() string { return "interrupt" }
