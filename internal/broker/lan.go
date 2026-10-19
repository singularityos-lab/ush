package broker

import (
	"fmt"

	ushlog "github.com/singularityos-lab/ush/internal/log"
	"github.com/singularityos-lab/ush/internal/policy"
)

func (s *Server) allowLan() error {
	if !s.confirmDialog(
		"USH - Share the local network",
		"Let ush use this computer's network directly?\n\n"+
			"Programs in the sandbox will be able to accept connections from other "+
			"devices on your local network and announce themselves there, for example "+
			"Spotify Connect, AirPlay or a development server. They will also reach "+
			"services that only listen on this computer.\n\n"+
			"It applies to new ush sessions; run 'restart' in the open ones.",
	) {
		ushlog.Warn("broker: local network sharing denied by user")
		return fmt.Errorf("local network sharing not confirmed by user")
	}
	s.mu.Lock()
	s.policy.Set(policy.CategoryLan, policy.LanResource, policy.DecisionAllow)
	err := s.policy.Save()
	s.mu.Unlock()
	if err == nil {
		ushlog.Info("broker: local network sharing allowed")
	}
	return err
}

func (s *Server) denyLan() error {
	s.mu.Lock()
	s.policy.Remove(policy.CategoryLan, policy.LanResource)
	err := s.policy.Save()
	s.mu.Unlock()
	return err
}

func (s *Server) lanShared() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return policy.LanShared(s.policy)
}
