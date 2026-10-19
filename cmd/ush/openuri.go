package main

import (
	"fmt"
	"os"

	"github.com/singularityos-lab/ush/internal/broker"
)

func runOpenURI(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: xdg-open <url>")
		return 1
	}
	client, err := broker.NewClient(os.Getenv("USH_SESSION_ID"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "xdg-open: %v\n", err)
		return 3
	}
	defer client.Close()
	if err := client.OpenURI(args[0]); err != nil {
		fmt.Fprintf(os.Stderr, "xdg-open: %v\n", err)
		return 4
	}
	return 0
}
