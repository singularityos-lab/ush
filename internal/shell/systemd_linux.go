// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package shell

import (
	"os"
	"syscall"
)

func sigterm() os.Signal {
	return syscall.SIGTERM
}

func systemdProcAttr() *syscall.SysProcAttr {
	// systemd --user must be the init process of the PID namespace.
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}
