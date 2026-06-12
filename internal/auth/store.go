package auth

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

type User struct {
	Username  string `json:"username"`
	PassHash  string `json:"passHash"`
	Role      Role   `json:"role"`
	CreatedAt string `json:"createdAt"`
}

type userFile struct {
	Users []User `json:"users"`
}

type UserStore struct {
	mu    sync.RWMutex
	users map[string]User
	path  string
}

func NewUserStore(path string) *UserStore {
	s := &UserStore{path: path, users: make(map[string]User)}
	s.load()
	if len(s.users) == 0 {
		s.bootstrap()
	}
	return s
}

func (s *UserStore) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var f userFile
	if err := json.Unmarshal(data, &f); err != nil {
		return
	}
	for _, u := range f.Users {
		s.users[u.Username] = u
	}
}

func (s *UserStore) flush() {
	users := make([]User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	data, _ := json.Marshal(userFile{Users: users})
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("auth: flush write error: %v", err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		log.Printf("auth: flush rename error: %v", err)
	}
}

func (s *UserStore) bootstrap() {
	hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	u := User{
		Username:  "admin",
		PassHash:  string(hash),
		Role:      RoleAdmin,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	s.users["admin"] = u
	s.flush()
	log.Println("WARNING: no users found — created default admin/admin. Change the password immediately.")
}

func (s *UserStore) Authenticate(username, password string) (User, bool) {
	s.mu.RLock()
	u, ok := s.users[username]
	s.mu.RUnlock()
	if !ok {
		return User{}, false
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PassHash), []byte(password)) != nil {
		return User{}, false
	}
	return u, true
}

func (s *UserStore) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	return users
}

func (s *UserStore) Create(username, password string, role Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[username]; exists {
		return fmt.Errorf("user %q already exists", username)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.users[username] = User{
		Username:  username,
		PassHash:  string(hash),
		Role:      role,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	s.flush()
	return nil
}

func (s *UserStore) Delete(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; !ok {
		return false
	}
	delete(s.users, username)
	s.flush()
	return true
}

func (s *UserStore) ChangePassword(username, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return fmt.Errorf("user not found")
	}
	u.PassHash = string(hash)
	s.users[username] = u
	s.flush()
	return nil
}
