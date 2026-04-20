// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package policy

import (
	"net"
	"net/url"
	"path/filepath"
	"strings"
)

// Risk describes the user-facing risk of a suggested permission scope.
type Risk string

const (
	RiskLow    Risk = "low"
	RiskMedium Risk = "medium"
	RiskHigh   Risk = "high"
)

// Scope is the permission grant the broker should show and optionally cache.
// It is derived from a narrower syscall/request resource, but remains bounded
// to the smallest useful parent scope.
type Scope struct {
	Category Category
	Resource string
	Risk     Risk
	Exact    bool
}

// SuggestScope converts an atomic request into the scope users should approve.
func SuggestScope(category Category, resource string) Scope {
	switch string(category) {
	case "filesystem":
		return filesystemScope(category, resource)
	case "network":
		return networkScope(category, resource)
	default:
		return Scope{
			Category: category,
			Resource: resource,
			Risk:     RiskMedium,
			Exact:    true,
		}
	}
}

func filesystemScope(category Category, resource string) Scope {
	op, raw := splitResourceOp(resource)
	if strings.HasPrefix(raw, "mount:") {
		return Scope{Category: category, Resource: resource, Risk: RiskHigh, Exact: true}
	}

	clean := filepath.Clean(raw)
	if clean == "." || clean == string(filepath.Separator) {
		return Scope{Category: category, Resource: joinResourceOp(op, clean), Risk: RiskHigh, Exact: true}
	}

	if isSensitivePath(clean) || isDangerousFilesystemBoundary(clean) || op == "write" || op == "delete" || op == "execute" {
		return Scope{Category: category, Resource: joinResourceOp(op, clean), Risk: RiskHigh, Exact: true}
	}

	parent := filepath.Dir(clean)
	if parent == "." || isDangerousFilesystemBoundary(parent) {
		return Scope{Category: category, Resource: joinResourceOp(op, clean), Risk: RiskHigh, Exact: true}
	}

	return Scope{
		Category: category,
		Resource: joinResourceOp(op, ensureTrailingSeparator(parent)),
		Risk:     RiskMedium,
		Exact:    false,
	}
}

func networkScope(category Category, resource string) Scope {
	if resource == "raw-socket" || resource == "outbound" {
		return Scope{Category: category, Resource: resource, Risk: RiskHigh, Exact: true}
	}

	if u, err := url.Parse(resource); err == nil && u.Scheme != "" && u.Host != "" {
		host := strings.ToLower(u.Hostname())
		port := u.Port()
		if port == "" {
			return Scope{Category: category, Resource: u.Scheme + "://" + host, Risk: RiskMedium, Exact: false}
		}
		return Scope{Category: category, Resource: u.Scheme + "://" + net.JoinHostPort(host, port), Risk: RiskMedium, Exact: false}
	}

	host, port, err := net.SplitHostPort(resource)
	if err == nil {
		host = strings.ToLower(strings.Trim(host, "[]"))
		return Scope{Category: category, Resource: "tcp://" + net.JoinHostPort(host, port), Risk: RiskMedium, Exact: false}
	}

	return Scope{Category: category, Resource: resource, Risk: RiskMedium, Exact: true}
}

func resourceMatchesScope(category Category, scope, requested string) bool {
	if scope == requested {
		return true
	}

	switch string(category) {
	case "filesystem":
		return filesystemResourceMatches(scope, requested)
	case "network":
		return networkResourceMatches(scope, requested)
	default:
		return false
	}
}

func filesystemResourceMatches(scope, requested string) bool {
	scopeOp, scopePath := splitResourceOp(scope)
	requestOp, requestPath := splitResourceOp(requested)
	if scopeOp != requestOp {
		return false
	}

	scopePath = filepath.Clean(scopePath)
	requestPath = filepath.Clean(requestPath)
	if scopePath == requestPath {
		return true
	}
	if isDangerousFilesystemBoundary(scopePath) || isSensitivePath(scopePath) {
		return false
	}

	scopePath = ensureTrailingSeparator(scopePath)
	return strings.HasPrefix(requestPath, scopePath)
}

func networkResourceMatches(scope, requested string) bool {
	if strings.HasSuffix(scope, ":*") {
		prefix := strings.TrimSuffix(scope, "*")
		return strings.HasPrefix(requested, prefix)
	}
	scopeURL, scopeErr := url.Parse(scope)
	requestURL, requestErr := url.Parse(requested)
	if scopeErr == nil && requestErr == nil &&
		scopeURL.Scheme != "" && requestURL.Scheme != "" &&
		scopeURL.Scheme == requestURL.Scheme &&
		networkAuthority(scopeURL) == networkAuthority(requestURL) {
		return true
	}
	return scope == requested
}

func networkAuthority(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func splitResourceOp(resource string) (string, string) {
	for _, op := range []string{"read", "write", "delete", "execute"} {
		prefix := op + ":"
		if strings.HasPrefix(resource, prefix) {
			return op, strings.TrimPrefix(resource, prefix)
		}
	}
	return "", resource
}

func joinResourceOp(op, resource string) string {
	if op == "" {
		return resource
	}
	return op + ":" + resource
}

func ensureTrailingSeparator(path string) string {
	if path == string(filepath.Separator) || strings.HasSuffix(path, string(filepath.Separator)) {
		return path
	}
	return path + string(filepath.Separator)
}

func isDangerousFilesystemBoundary(path string) bool {
	clean := filepath.Clean(path)
	switch clean {
	case "/", "/home", "/root", "/etc", "/usr", "/var", "/tmp", "/proc", "/sys", "/dev", "/run":
		return true
	default:
		return false
	}
}

func isSensitivePath(path string) bool {
	clean := filepath.Clean(path)
	parts := strings.Split(clean, string(filepath.Separator))
	for _, part := range parts {
		switch part {
		case ".ssh", ".gnupg", ".aws", ".kube", ".docker", "id_rsa", "id_ed25519":
			return true
		}
		if part == ".env" || strings.HasPrefix(part, ".env.") {
			return true
		}
		lower := strings.ToLower(part)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "token") {
			return true
		}
	}
	return false
}
