// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package policy implements the policy engine for the USH broker.
// Policies are saved in JSON and manage allow/deny decisions
// by category and resource.
package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Category is a permission category.
type Category string

const (
	CategoryFileOutsideGuest Category = "file.outside_guest"
	CategoryNetElevated      Category = "net.elevated"
	CategoryDBusSensitive    Category = "dbus.sensitive"
	CategoryMountSpecial     Category = "mount.special"
	CategoryDeviceAccess     Category = "device.access"
	CategoryFuseLoop         Category = "fs.fuse_loop"
	CategoryHostIntrospect   Category = "host.introspect"
	// Notifications and portal: allow by default.
	CategoryNotifications Category = "dbus.notifications"
	CategoryPortal        Category = "dbus.portal"
	// SignaturesUpdate gates the Singularity Guard daemon (singd) fetching
	// updated malware signatures over the network. Defaults to ask (no rule),
	// so a signature update never reaches the network without user consent.
	CategorySignaturesUpdate Category = "signatures.update"
)

// DecisionValue is the value of a policy decision.
type DecisionValue string

const (
	DecisionAllow DecisionValue = "allow"
	DecisionDeny  DecisionValue = "deny"
	DecisionAsk   DecisionValue = "ask"
)

// Rule is a policy rule.
type Rule struct {
	Category Category      `json:"category"`
	Resource string        `json:"resource"`
	Decision DecisionValue `json:"decision"`
}

// Engine manages USH policies.
type Engine struct {
	mu    sync.RWMutex
	rules map[string]*Rule
	path  string
}

// NewEngine creates a new policy engine.
func NewEngine(path string) (*Engine, error) {
	e := &Engine{
		rules: make(map[string]*Rule),
		path:  path,
	}

	if err := e.Load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	// Default rules for safe categories.
	e.setDefault(CategoryNotifications, "*", DecisionAllow)
	e.setDefault(CategoryPortal, "*", DecisionAllow)

	return e, nil
}

// Check checks if a rule exists for category+resource.
// Returns the decision and true if a rule exists.
func (e *Engine) Check(cat Category, resource string) (DecisionValue, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Look for an exact rule.
	key := ruleKey(cat, resource)
	if r, ok := e.rules[key]; ok {
		return r.Decision, true
	}

	// Look for the narrowest saved scope that contains this resource.
	var best *Rule
	for _, r := range e.rules {
		if r.Category != cat || r.Resource == "*" {
			continue
		}
		if !resourceMatchesScope(cat, r.Resource, resource) {
			continue
		}
		if best == nil || len(r.Resource) > len(best.Resource) {
			best = r
		}
	}
	if best != nil {
		return best.Decision, true
	}

	// Look for a wildcard rule per category.
	key = ruleKey(cat, "*")
	if r, ok := e.rules[key]; ok {
		return r.Decision, true
	}

	return DecisionAsk, false
}

// Set sets a policy rule.
func (e *Engine) Set(cat Category, resource string, decision DecisionValue) {
	e.mu.Lock()
	defer e.mu.Unlock()

	key := ruleKey(cat, resource)
	e.rules[key] = &Rule{
		Category: cat,
		Resource: resource,
		Decision: decision,
	}
}

// Remove removes a policy rule.
func (e *Engine) Remove(cat Category, resource string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.rules, ruleKey(cat, resource))
}

// List returns all rules.
func (e *Engine) List() []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rules := make([]*Rule, 0, len(e.rules))
	for _, r := range e.rules {
		rules = append(rules, r)
	}
	return rules
}

// Load loads policies from the file.
func (e *Engine) Load() error {
	data, err := os.ReadFile(e.path)
	if err != nil {
		return err
	}

	var rules []*Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range rules {
		e.rules[ruleKey(r.Category, r.Resource)] = r
	}
	return nil
}

// Save saves policies to file.
func (e *Engine) Save() error {
	e.mu.RLock()
	rules := make([]*Rule, 0, len(e.rules))
	for _, r := range e.rules {
		rules = append(rules, r)
	}
	e.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(e.path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(e.path, data, 0600)
}

func (e *Engine) setDefault(cat Category, resource string, decision DecisionValue) {
	key := ruleKey(cat, resource)
	if _, exists := e.rules[key]; !exists {
		e.rules[key] = &Rule{
			Category: cat,
			Resource: resource,
			Decision: decision,
		}
	}
}

func ruleKey(cat Category, resource string) string {
	return string(cat) + ":" + resource
}
