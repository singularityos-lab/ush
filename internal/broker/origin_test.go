// SPDX-License-Identifier: GPL-3.0-or-later

package broker

import (
	"strings"
	"testing"
	"time"

	"github.com/singularityos-lab/ush/internal/policy"
)

func TestParseOrigin(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantRemote bool
		wantKind   string
		wantLabel  string
	}{
		{"absent is local", "", false, "", ""},
		{"explicit local", "local", false, "", ""},
		{"whitespace is local", "   ", false, "", ""},
		{"sdb with label", "sdb:workstation", true, OriginKindSDB, "workstation"},
		{"sdb label is trimmed", "sdb: workstation ", true, OriginKindSDB, "workstation"},
		{"sdb without label", "sdb:", true, OriginKindSDB, ""},
		{"unrecognised is remote", "something-else", true, "unknown", ""},
		{"near miss is remote", "sdb", true, "unknown", ""},
		{"lookalike prefix is remote", "localhost", true, "unknown", ""},
	}

	for _, c := range cases {
		got := parseOrigin(c.raw)
		if got.Remote != c.wantRemote {
			t.Errorf("%s: parseOrigin(%q).Remote = %v, want %v", c.name, c.raw, got.Remote, c.wantRemote)
		}
		if got.Kind != c.wantKind {
			t.Errorf("%s: parseOrigin(%q).Kind = %q, want %q", c.name, c.raw, got.Kind, c.wantKind)
		}
		if got.Label != c.wantLabel {
			t.Errorf("%s: parseOrigin(%q).Label = %q, want %q", c.name, c.raw, got.Label, c.wantLabel)
		}
	}
}

// The banner is the only thing that tells the user the action was not started
// here, so a remote origin must always produce one, and an origin whose peer is
// not identified must say so rather than stay silent.
func TestOriginBanner(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		want     string
		wantNone bool
	}{
		{name: "local has no banner", raw: "", wantNone: true},
		{name: "named host", raw: "sdb:workstation", want: "paired host: workstation"},
		{name: "unlabelled sdb", raw: "sdb:", want: "UNIDENTIFIED host"},
		{name: "unknown origin", raw: "whatever", want: "UNIDENTIFIED host"},
	}

	for _, c := range cases {
		banner := parseOrigin(c.raw).banner()
		if c.wantNone {
			if banner != "" {
				t.Errorf("%s: banner = %q, want empty", c.name, banner)
			}
			continue
		}
		if !strings.Contains(banner, "REMOTELY") {
			t.Errorf("%s: banner = %q, does not say the request is remote", c.name, banner)
		}
		if !strings.Contains(banner, c.want) {
			t.Errorf("%s: banner = %q, want it to contain %q", c.name, banner, c.want)
		}
	}
}

// The banner leads the dialog reason: a caller-supplied reason must not be able
// to push the remote warning out of view, nor forge one with control characters.
func TestRemoteReasonLeadsWithBanner(t *testing.T) {
	got := remoteReason("read the build log", parseOrigin(SDBOrigin("workstation")))
	if !strings.HasPrefix(got, "REQUESTED REMOTELY") {
		t.Errorf("reason = %q, want it to start with the remote banner", got)
	}
	if !strings.Contains(got, "read the build log") {
		t.Errorf("reason = %q, want it to keep the caller reason", got)
	}

	forged := remoteReason("x", parseOrigin(SDBOrigin("safe\nlocal request")))
	if strings.Count(strings.SplitN(forged, "\n\n", 2)[0], "\n") != 0 {
		t.Errorf("banner is multi-line, a label can forge dialog lines: %q", forged)
	}
}

// Negative proof: with the broker in non-interactive mode set to allow
// everything, a local request is answered "allow" and an identical request
// attributed to the debug bridge is refused. There is no user present to be
// told the action is remote, so it fails closed.
func TestRemoteRequestIsNotAutoApproved(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "allow_always")

	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Stop()
	if !srv.auto.enabled {
		t.Fatal("auto mode did not activate, test would not prove anything")
	}

	if got := srv.requestPermission("network", "outbound", "test", "session-1"); got != "allow_always" {
		t.Fatalf("local decision = %q, want allow_always (auto mode baseline)", got)
	}

	cases := []struct {
		name   string
		origin string
	}{
		{"paired host", SDBOrigin("workstation")},
		{"unlabelled bridge", SDBOrigin("")},
		{"unrecognised origin", "something-else"},
	}
	for _, c := range cases {
		got := srv.requestPermissionFrom("network", "outbound", "test", "session-1", parseOrigin(c.origin))
		if got != "deny" {
			t.Errorf("%s: decision = %q, want deny", c.name, got)
		}
	}
}

// Negative proof: a grant the user gave to a LOCAL action must not answer for a
// remote one. The same server, with the rule cached and matching, still refuses
// the remote request while the local request is served from the cache.
func TestRemoteRequestIgnoresCachedGrant(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "deny")

	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Stop()

	srv.policy.Set("network", "outbound", policy.DecisionAllow)

	if got := srv.requestPermission("network", "outbound", "test", "session-1"); got != "allow" {
		t.Fatalf("local decision = %q, want allow (from cache)", got)
	}

	got := srv.requestPermissionFrom("network", "outbound", "test", "session-1",
		parseOrigin(SDBOrigin("workstation")))
	if got != "deny" {
		t.Errorf("remote decision = %q, want deny: a cached local grant answered a remote request", got)
	}
}

// A remote request must not join a local prompt that is already on screen: the
// user is being asked about the local action, not about the remote one.
func TestRemoteRequestDoesNotJoinLocalInflight(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "allow")

	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Stop()

	scope := policy.SuggestScope("network", "tcp://203.0.113.10:443")
	inflight := &inflightPermission{done: make(chan struct{}), decision: "allow_always"}
	srv.mu.Lock()
	srv.inflight[permissionInflightKey("network", scope.Resource)] = inflight
	srv.mu.Unlock()

	done := make(chan string, 1)
	go func() {
		done <- srv.requestPermissionFrom("network", "tcp://203.0.113.10:443", "test", "session-1",
			parseOrigin(SDBOrigin("workstation")))
	}()

	select {
	case got := <-done:
		if got != "deny" {
			t.Errorf("remote decision = %q, want deny", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("remote request blocked on a local in-flight prompt")
	}
}

// A remote request must never leave a rule behind: nothing it does may widen
// what a later local request is allowed to do without asking.
func TestRemoteRequestPersistsNothing(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "allow_always")

	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Stop()

	before := len(srv.policy.List())

	srv.requestPermissionFrom("network", "outbound", "test", "session-1",
		parseOrigin(SDBOrigin("workstation")))

	if after := len(srv.policy.List()); after != before {
		t.Errorf("policy rules went from %d to %d after a remote request, want unchanged", before, after)
	}
	if _, ok := srv.policy.Check("network", "outbound"); ok {
		t.Error("remote request cached a decision")
	}
}

// Regression: the local path is unchanged. An empty origin field on the wire, as
// every pre-existing client sends, is handled exactly like a direct local call.
func TestAbsentOriginKeepsLocalBehaviour(t *testing.T) {
	t.Setenv("USH_BROKER_AUTO", "allow_always")

	srv, err := NewServer(t.TempDir())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Stop()

	resp := srv.dispatch(rpcRequest{
		Method:    "RequestPermission",
		Category:  "network",
		Resource:  "outbound",
		Reason:    "test",
		SessionID: "session-1",
	})
	if resp.Decision != "allow_always" {
		t.Fatalf("decision = %q, want allow_always", resp.Decision)
	}

	if _, ok := srv.policy.Check("network", "outbound"); !ok {
		t.Error("local allow_always did not persist a rule, local behaviour changed")
	}
}
