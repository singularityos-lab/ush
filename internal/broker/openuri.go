package broker

import (
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"syscall"
)

func validOpenURI(uri string) error {
	if len(uri) > 8192 || strings.ContainsAny(uri, "\x00\r\n") {
		return fmt.Errorf("invalid uri")
	}
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid uri: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		if u.Host == "" {
			return fmt.Errorf("invalid uri: no host")
		}
	case "mailto":
	default:
		return fmt.Errorf("scheme %q is not opened from a session", u.Scheme)
	}
	return nil
}

func (s *Server) openURI(uri string) error {
	if err := validOpenURI(uri); err != nil {
		return err
	}
	cmd := exec.Command("gio", "open", uri)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open %s: %w", dialogSafe(uri), err)
	}
	go cmd.Wait()
	return nil
}
