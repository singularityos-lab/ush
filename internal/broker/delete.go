package broker

import (
	"fmt"
	"os/exec"

	"github.com/godbus/dbus/v5"
	ushlog "github.com/singularityos-lab/ush/internal/log"
)

func (s *Server) confirmMassDelete(app, where string) bool {
	title := "Many files are being deleted"
	body := fmt.Sprintf("%s is deleting many files in %s.\n\n"+
		"It is paused until you choose. Block it if you did not start this.", app, where)
	ok := s.choiceDialog(title, body, "Allow", "Block and Stop")
	if ok {
		ushlog.Warn("broker: mass deletion allowed by user", "app", app, "where", where)
	} else {
		ushlog.Warn("broker: mass deletion blocked", "app", app, "where", where)
	}
	return ok
}

func (s *Server) choiceDialog(title, body, allowLabel, blockLabel string) bool {
	if s.auto != nil && s.auto.enabled {
		return s.auto.confirmVerdict("confirm", title)
	}
	if conn, err := dbus.ConnectSessionBus(); err == nil {
		defer conn.Close()
		if s.portalAvailable(conn) {
			var allowed bool
			call := conn.Object(PortalBusName, dbus.ObjectPath(PortalObjPath)).
				Call(PortalInterface+".ShowChoice", 0, title, body, allowLabel, blockLabel)
			if call.Err == nil && call.Store(&allowed) == nil {
				return allowed
			}
		}
	}
	if _, err := exec.LookPath("zenity"); err == nil {
		return exec.Command("zenity", "--question", "--title="+title, "--text="+body,
			"--ok-label="+allowLabel, "--cancel-label="+blockLabel, "--width=500").Run() == nil
	}
	return s.confirmDialog(title, body+"\n\nConfirm allows it, anything else blocks it.")
}
