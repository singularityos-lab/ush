package shell

import (
	"context"
	"fmt"
	"os"

	"github.com/singularityos-lab/ush/internal/broker"
	"mvdan.cc/sh/v3/interp"
)

func (sh *Shell) builtinCpak(ctx context.Context, args []string) error {
	req, err := broker.ParseCpakRequest(args)
	if err != nil {
		return err
	}
	hc := interp.HandlerCtx(ctx)
	stdin, ok := hc.Stdin.(*os.File)
	if !ok {
		return fmt.Errorf("cpak: host commands require terminal or pipe descriptors")
	}
	client, err := broker.NewClient(sh.sessionID)
	if err != nil {
		return err
	}
	defer client.Close()
	code, err := client.RunCpak(ctx, req, stdin, hc.Stdout, hc.Stderr)
	if err != nil {
		return err
	}
	if code != 0 {
		return interp.NewExitStatus(uint8(code))
	}
	return nil
}
