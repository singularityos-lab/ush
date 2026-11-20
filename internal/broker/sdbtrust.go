// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

package broker

import (
	"time"

	"github.com/singularityos-lab/ush/internal/policy"
)

const (
	sdbTrustCategory     policy.Category = "sdb.trust"
	sdbAutoApproveRule                   = "auto-approve"
	sdbGrantSourceAlways                 = "sdb_remembered_always"
	sdbGrantSourceSess                   = "sdb_remembered_session"
	sdbGrantSourceAuto                   = "sdb_auto_approve"
)

func sdbGrantKey(peer, action string) string {
	return peer + "|" + action
}

func (s *Server) sdbAutoApprove() bool {
	d, ok := s.policy.Check(sdbTrustCategory, sdbAutoApproveRule)
	return ok && d == policy.DecisionAllow
}

func (s *Server) setSdbAutoApprove(enabled bool) error {
	if enabled {
		s.policy.Set(sdbTrustCategory, sdbAutoApproveRule, policy.DecisionAllow)
	} else {
		s.policy.Remove(sdbTrustCategory, sdbAutoApproveRule)
	}
	return s.policy.Save()
}

func (s *Server) sdbRemembered(peer, action string) (string, bool) {
	if peer == "" {
		return "", false
	}
	if s.sdbAutoApprove() {
		return sdbGrantSourceAuto, true
	}
	key := sdbGrantKey(peer, action)
	if d, ok := s.policy.Check(sdbTrustCategory, key); ok && d == policy.DecisionAllow {
		return sdbGrantSourceAlways, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sdbSession[key] {
		return sdbGrantSourceSess, true
	}
	return "", false
}

func (s *Server) sdbRemember(peer, action, raw string) {
	if peer == "" {
		return
	}
	key := sdbGrantKey(peer, action)
	switch raw {
	case "allow_always":
		s.policy.Set(sdbTrustCategory, key, policy.DecisionAllow)
		_ = s.policy.Save()
	case "allow_session":
		s.mu.Lock()
		s.sdbSession[key] = true
		s.mu.Unlock()
	}
}

func (s *Server) resetSdbApprovals() error {
	for _, r := range s.policy.List() {
		if r.Category == sdbTrustCategory && r.Resource != sdbAutoApproveRule {
			s.policy.Remove(r.Category, r.Resource)
		}
	}
	s.mu.Lock()
	s.sdbSession = make(map[string]bool)
	s.mu.Unlock()
	return s.policy.Save()
}

func (s *Server) auditSdbGrant(resource, sessionID, source string, origin Origin) {
	s.auditLog.Write(AuditEntry{
		Timestamp: time.Now(),
		SessionID: sessionID,
		Category:  sdbElevateCategory,
		Resource:  resource,
		Decision:  "allow",
		Source:    source,
		Origin:    origin.auditValue(),
	})
}
