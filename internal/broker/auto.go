// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// auto.go implements the broker's non-interactive ("auto") decision mode for
// headless testing, CI, and red-team harnesses. When USH_BROKER_AUTO is set the
// broker skips every dialog and decides from a default verdict plus an optional
// ordered rules file, appending every decision to a JSONL log.
//
// Environment:
//
//	USH_BROKER_AUTO           default verdict: allow | deny | allow_session |
//	                          allow_always. Presence of this var enables auto
//	                          mode. Unset => interactive dialogs as before.
//	USH_BROKER_RULES          path to a JSON rules file (see Rule). First match
//	                          wins; if none match, the default verdict is used.
//	USH_BROKER_CONFIRM        yes | no (default no): answer for the yes/no
//	                          confirmations gating AllowApp / RevokePermission.
//	USH_BROKER_DECISION_LOG   path to a JSONL file; every auto decision is
//	                          appended as one record.
//
// SECURITY: auto mode removes the human from the loop, so it must NEVER be the
// default. It activates only when USH_BROKER_AUTO is explicitly set in the
// broker process's own environment. It is a testing affordance, not a
// production policy source.
package broker

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	ushlog "github.com/singularityos-lab/ush/internal/log"
)

// Rule is one entry in the auto-mode rules file. A request matches when its
// category equals Category (empty Category matches any) and its resource
// matches Resource according to Match. The first matching rule's Decision wins.
type Rule struct {
	Category string `json:"category"`
	Resource string `json:"resource"`
	// Match is one of: "exact" (default), "prefix", "substr", "regex".
	Match    string `json:"match"`
	Decision string `json:"decision"`

	re *regexp.Regexp // compiled lazily for Match=="regex"
}

// autoDecider holds the parsed auto-mode configuration. A nil *autoDecider, or
// one with enabled==false, means interactive mode (no auto answers).
type autoDecider struct {
	enabled bool
	def     string // default verdict
	confirm bool   // answer for confirmDialog
	rules   []*Rule
	logPath string
	logMu   sync.Mutex
}

// autoDecisionRecord is one line in the decision log.
type autoDecisionRecord struct {
	Timestamp time.Time `json:"ts"`
	Kind      string    `json:"kind"` // "permission" or "confirm"
	Category  string    `json:"category"`
	Resource  string    `json:"resource"`
	Reason    string    `json:"reason,omitempty"`
	Decision  string    `json:"decision"`
	Rule      int       `json:"rule"` // index of the matched rule, -1 if default
}

// newAutoDecider reads the USH_BROKER_* environment and returns a decider. The
// returned decider is always non-nil; check .enabled before using it.
func newAutoDecider() *autoDecider {
	def := strings.TrimSpace(os.Getenv("USH_BROKER_AUTO"))
	d := &autoDecider{
		confirm: strings.EqualFold(strings.TrimSpace(os.Getenv("USH_BROKER_CONFIRM")), "yes"),
		logPath: strings.TrimSpace(os.Getenv("USH_BROKER_DECISION_LOG")),
	}
	if def == "" {
		return d // disabled
	}
	d.enabled = true
	d.def = normalizeDecision(def)

	if rulesPath := strings.TrimSpace(os.Getenv("USH_BROKER_RULES")); rulesPath != "" {
		if rules, err := loadRules(rulesPath); err != nil {
			ushlog.Warn("broker: auto rules load failed, using default verdict only",
				"path", rulesPath, "err", err)
		} else {
			d.rules = rules
		}
	}

	ushlog.Info("broker: AUTO decision mode active (no user dialogs)",
		"default", d.def, "rules", len(d.rules), "confirm", d.confirm, "log", d.logPath)
	return d
}

func normalizeDecision(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow", "allow_session", "allow_always", "deny", "deny_always":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return "deny" // anything unrecognized fails safe
	}
}

func loadRules(path string) ([]*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rules []*Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	for _, r := range rules {
		r.Decision = normalizeDecision(r.Decision)
		if strings.EqualFold(r.Match, "regex") {
			re, err := regexp.Compile(r.Resource)
			if err != nil {
				ushlog.Warn("broker: auto rule has invalid regex, will never match",
					"resource", r.Resource, "err", err)
				continue
			}
			r.re = re
		}
	}
	return rules, nil
}

func (r *Rule) matches(category, resource string) bool {
	if r.Category != "" && !strings.EqualFold(r.Category, category) {
		return false
	}
	switch strings.ToLower(r.Match) {
	case "prefix":
		return strings.HasPrefix(resource, r.Resource)
	case "substr":
		return strings.Contains(resource, r.Resource)
	case "regex":
		return r.re != nil && r.re.MatchString(resource)
	default: // exact
		return resource == r.Resource
	}
}

// decide returns the scripted verdict for a permission request and logs it.
func (d *autoDecider) decide(category, resource, reason string) string {
	decision := d.def
	matched := -1
	for i, r := range d.rules {
		if r.matches(category, resource) {
			decision = r.Decision
			matched = i
			break
		}
	}
	d.log(autoDecisionRecord{
		Timestamp: time.Now(),
		Kind:      "permission",
		Category:  category,
		Resource:  resource,
		Reason:    reason,
		Decision:  decision,
		Rule:      matched,
	})
	return decision
}

// confirmVerdict returns the scripted yes/no answer for a confirmation gate.
func (d *autoDecider) confirmVerdict(category, resource string) bool {
	answer := "deny"
	if d.confirm {
		answer = "allow"
	}
	d.log(autoDecisionRecord{
		Timestamp: time.Now(),
		Kind:      "confirm",
		Category:  category,
		Resource:  resource,
		Decision:  answer,
		Rule:      -1,
	})
	return d.confirm
}

func (d *autoDecider) log(rec autoDecisionRecord) {
	if d.logPath == "" {
		return
	}
	d.logMu.Lock()
	defer d.logMu.Unlock()
	f, err := os.OpenFile(d.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	if data, err := json.Marshal(rec); err == nil {
		f.Write(append(data, '\n'))
	}
}
