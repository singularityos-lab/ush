// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Mirko Brombin <brombin94@gmail.com>

// Package session manages ush guest sessions.
// Each session has a unique ID, an optional ephemeral layer and lifecycle metadata.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// State is the state of a session.
type State string

const (
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateStopped  State = "stopped"
)

// Session describes an active guest session.
type Session struct {
	ID         string    `json:"id"`
	PID        int       `json:"pid"`
	State      State     `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	StorageDir string    `json:"storage_dir"`
	// EphemeralLayerID is the ephemeral layer for this session (if not persistent).
	EphemeralLayerID string `json:"ephemeral_layer_id,omitempty"`
}

// Manager manages active ush sessions.
type Manager struct {
	mu          sync.Mutex
	sessionsDir string
	sessions    map[string]*Session
}

// NewManager creates a new session manager.
func NewManager(storageDir string) *Manager {
	return &Manager{
		sessionsDir: filepath.Join(storageDir, "sessions"),
		sessions:    make(map[string]*Session),
	}
}

// New creates a new session and registers it.
func (m *Manager) New(ephemeral bool) (*Session, error) {
	id, err := newID()
	if err != nil {
		return nil, fmt.Errorf("session: ID generation: %w", err)
	}

	sess := &Session{
		ID:         id,
		PID:        os.Getpid(),
		State:      StateStarting,
		CreatedAt:  time.Now(),
		StorageDir: m.sessionsDir,
	}
	if ephemeral {
		sess.EphemeralLayerID = id
	}

	m.mu.Lock()
	m.sessions[id] = sess
	m.mu.Unlock()

	if err := m.persist(sess); err != nil {
		return nil, err
	}

	return sess, nil
}

// SetRunning marks the session as running.
func (m *Manager) SetRunning(id string) error {
	return m.update(id, func(s *Session) { s.State = StateRunning })
}

// SetStopped marks the session as stopped.
func (m *Manager) SetStopped(id string) error {
	return m.update(id, func(s *Session) { s.State = StateStopped })
}

// Remove removes the session from the registry.
func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	delete(m.sessions, id)
	m.mu.Unlock()

	path := m.sessionPath(id)
	return os.Remove(path)
}

// List returns all active sessions.
func (m *Manager) List() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		result = append(result, s)
	}
	return result
}

func (m *Manager) update(id string, fn func(*Session)) error {
	m.mu.Lock()
	s, ok := m.sessions[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("session: %s not found", id)
	}
	fn(s)
	m.mu.Unlock()
	return m.persist(s)
}

func (m *Manager) persist(s *Session) error {
	if err := os.MkdirAll(m.sessionsDir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.sessionPath(s.ID), data, 0600)
}

func (m *Manager) sessionPath(id string) string {
	return filepath.Join(m.sessionsDir, id+".json")
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
