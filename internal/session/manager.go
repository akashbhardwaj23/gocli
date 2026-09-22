package session

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/akashbhardwaj23/cli-auth/internal/models"
)

type Session struct {
	Token     string
	User      *models.User
	ExpiresAt time.Time
}

type Manager struct {
	mu       sync.Mutex
	sessions map[string]Session
	timeout  time.Duration
}

func NewManager(minutes int) *Manager {
	return &Manager{
		sessions: make(map[string]Session),
		timeout:  time.Duration(minutes) * time.Minute,
	}
}

func (m *Manager) Create(
	user *models.User,
) (Session, error) {

	randomBytes := make([]byte, 32)

	if _, err := rand.Read(randomBytes); err != nil {
		return Session{}, err
	}

	newSession := Session{
		Token:     hex.EncodeToString(randomBytes),
		User:      user,
		ExpiresAt: time.Now().Add(m.timeout),
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[newSession.Token] = newSession

	return newSession, nil
}

func (m *Manager) Get(
	token string,
) (Session, bool) {

	m.mu.Lock()
	defer m.mu.Unlock()

	currentSession, exists :=
		m.sessions[token]

	if !exists {
		return Session{}, false
	}

	if time.Now().After(
		currentSession.ExpiresAt,
	) {
		delete(m.sessions, token)

		return Session{}, false
	}

	return currentSession, true
}

func (m *Manager) Delete(token string) {

	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, token)
}
