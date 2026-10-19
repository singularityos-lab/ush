package main

import "golang.org/x/sys/unix"

func dropAmbientCaps() error {
	return unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
}
