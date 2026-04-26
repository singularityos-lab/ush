// SPDX-License-Identifier: GPL-3.0-or-later

package pkg

import (
	"testing"
)

func TestClassifyScriptContent(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    ScriptRisk
	}{
		{
			name:    "safe script",
			content: `#!/bin/sh\necho "installed"`,
			want:    RiskSafe,
		},
		{
			name:    "systemctl enable",
			content: `#!/bin/sh\nsystemctl enable myservice`,
			want:    RiskWarn,
		},
		{
			name:    "systemctl start",
			content: `#!/bin/sh\nsystemctl start something.service`,
			want:    RiskWarn,
		},
		{
			name:    "chmod setuid",
			content: `#!/bin/sh\nchmod +s /usr/bin/myprogram`,
			want:    RiskBlock,
		},
		{
			name:    "setcap",
			content: `#!/bin/sh\nsetcap cap_net_admin+ep /usr/bin/foo`,
			want:    RiskBlock,
		},
		{
			name:    "modprobe",
			content: `#!/bin/sh\nmodprobe new_module`,
			want:    RiskBlock,
		},
		{
			name:    "insmod",
			content: `#!/bin/sh\ninsmod /lib/modules/foo.ko`,
			want:    RiskBlock,
		},
		{
			name:    "proc/sys write",
			content: `#!/bin/sh\necho 1 > /proc/sys/net/ipv4/ip_forward`,
			want:    RiskBlock,
		},
		{
			name:    "dbus-send",
			content: `#!/bin/sh\ndbus-send --system --type=method_call /`,
			want:    RiskWarn,
		},
		{
			name:    "adduser",
			content: `#!/bin/sh\nadduser --system myuser`,
			want:    RiskWarn,
		},
		{
			name:    "update-rc.d",
			content: `#!/bin/sh\nupdate-rc.d myservice defaults`,
			want:    RiskWarn,
		},
		{
			name:    "ldconfig",
			content: `#!/bin/sh\nldconfig`,
			want:    RiskWarn,
		},
		{
			name:    "block beats warn",
			content: `#!/bin/sh\nsystemctl enable foo\nchmod +s /usr/bin/bar`,
			want:    RiskBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyScriptContent(tt.content)
			if got != tt.want {
				t.Errorf("classifyScriptContent(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestRiskOrdering(t *testing.T) {
	// BLOCK must always prevail over WARN.
	content := "systemctl enable foo\nchmod +s /usr/bin/bar"
	got := classifyScriptContent(content)
	if got != RiskBlock {
		t.Errorf("BLOCK should prevail over WARN, got %q", got)
	}
}
