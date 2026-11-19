package auth

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Area is a part of the product a role grants separately.
type Area string

const (
	AreaTracing         Area = "tracing"
	AreaNetwork         Area = "network"
	AreaAdmission       Area = "admission"
	AreaQuarantine      Area = "quarantine"
	AreaEvents          Area = "events"
	AreaVulnerabilities Area = "vulnerabilities"
	AreaNotifications   Area = "notifications"
	AreaSystem          Area = "system"
)

// Areas is every area, in the order a role editor shows them.
var Areas = []Area{
	AreaTracing, AreaNetwork, AreaAdmission, AreaQuarantine,
	AreaEvents, AreaVulnerabilities, AreaNotifications, AreaSystem,
}

// Level is how much of an area a role grants. Manage includes view.
type Level string

const (
	LevelNone   Level = "none"
	LevelView   Level = "view"
	LevelManage Level = "manage"
)

func (l Level) rank() int {
	switch l {
	case LevelManage:
		return 2
	case LevelView:
		return 1
	}
	return 0
}

// Permissions is the level a role grants on each area. An area that is not
// there is none, so a release can add an area without touching stored roles.
type Permissions map[Area]Level

// Can reports whether the permissions reach the level on the area.
func (p Permissions) Can(a Area, l Level) bool {
	return p[a].rank() >= l.rank()
}

// RoleDef is a role: a name and what it grants.
type RoleDef struct {
	Name        Role        `json:"name"`
	Permissions Permissions `json:"permissions"`
	// Admin and viewer: always there, never edited or deleted. Their names are
	// what every account from before roles could be made carries.
	BuiltIn bool `json:"builtIn,omitempty"`
}

func all(l Level) Permissions {
	p := Permissions{}
	for _, a := range Areas {
		p[a] = l
	}
	return p
}

func builtInRoles() []RoleDef {
	// A viewer is what a viewer was shown before: no settings, no accounts, and
	// no alert or syslog targets, whose URLs are credentials.
	viewer := all(LevelView)
	viewer[AreaNotifications] = LevelNone
	viewer[AreaSystem] = LevelNone
	return []RoleDef{
		{Name: RoleAdmin, Permissions: all(LevelManage), BuiltIn: true},
		{Name: RoleViewer, Permissions: viewer, BuiltIn: true},
	}
}

var (
	ErrRoleExists      = errors.New("a role with this name already exists")
	ErrRoleNotFound    = errors.New("role not found")
	ErrRoleBuiltIn     = errors.New("a built-in role cannot be changed")
	ErrRoleName        = errors.New("a role name is 1 to 40 letters, digits, spaces, - or _")
	ErrRolePermissions = errors.New("a role gives each area none, view or manage")
)

var roleNameRE = regexp.MustCompile(`^[A-Za-z0-9 _-]{1,40}$`)

// RoleStore holds the roles made here, beside the two that are built in.
type RoleStore struct {
	mu    sync.RWMutex
	path  string // empty: kept in memory only
	roles map[string]RoleDef
}

// NewRoleStore reads the roles kept at path. With no path nothing is written,
// which is what a test and a handler tree built without one get.
func NewRoleStore(path string) *RoleStore {
	s := &RoleStore{path: path, roles: map[string]RoleDef{}}
	if path == "" {
		return s
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s
	}
	// A file that could not be read this once is not a file with no roles in
	// it: starting anyway would leave every account on a custom role with none.
	if err != nil {
		log.Fatalf("auth: cannot read %s: %v", path, err)
	}
	var stored []RoleDef
	if err := json.Unmarshal(data, &stored); err != nil {
		log.Printf("auth: %s is not valid JSON (%v); kept as %s.corrupt", path, err, path)
		_ = os.Rename(path, path+".corrupt")
		return s
	}
	for _, r := range stored {
		r.BuiltIn = false
		r.Permissions = cleanPermissions(r.Permissions)
		s.roles[roleKey(r.Name)] = r
	}
	return s
}

// roleKey makes names unique without regard to case.
func roleKey(name Role) string { return strings.ToLower(string(name)) }

// cleanPermissions keeps the areas and levels this release knows.
func cleanPermissions(p Permissions) Permissions {
	out := Permissions{}
	for _, a := range Areas {
		switch p[a] {
		case LevelView, LevelManage:
			out[a] = p[a]
		default:
			out[a] = LevelNone
		}
	}
	return out
}

func validPermissions(p Permissions) bool {
	for a, l := range p {
		known := false
		for _, k := range Areas {
			known = known || k == a
		}
		if !known || (l != LevelNone && l != LevelView && l != LevelManage) {
			return false
		}
	}
	return true
}

func builtIn(name Role) (RoleDef, bool) {
	for _, r := range builtInRoles() {
		if roleKey(r.Name) == roleKey(name) {
			return r, true
		}
	}
	return RoleDef{}, false
}

// Get returns the role an account's role name stands for. The name is matched
// exactly: it is what was stored when the account was given the role.
func (s *RoleStore) Get(name Role) (RoleDef, bool) {
	if r, ok := builtIn(name); ok && r.Name == name {
		return r, true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[roleKey(name)]
	if !ok || r.Name != name {
		return RoleDef{}, false
	}
	return r, true
}

// List returns the built-in roles, then the others by name.
func (s *RoleStore) List() []RoleDef {
	s.mu.RLock()
	defer s.mu.RUnlock()
	custom := make([]RoleDef, 0, len(s.roles))
	for _, r := range s.roles {
		custom = append(custom, r)
	}
	sort.Slice(custom, func(i, j int) bool { return roleKey(custom[i].Name) < roleKey(custom[j].Name) })
	return append(builtInRoles(), custom...)
}

func (s *RoleStore) Create(def RoleDef) error {
	name := Role(strings.TrimSpace(string(def.Name)))
	if !roleNameRE.MatchString(string(name)) {
		return ErrRoleName
	}
	if !validPermissions(def.Permissions) {
		return ErrRolePermissions
	}
	if _, taken := builtIn(name); taken {
		return ErrRoleExists
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.roles[roleKey(name)]; taken {
		return ErrRoleExists
	}
	s.roles[roleKey(name)] = RoleDef{Name: name, Permissions: cleanPermissions(def.Permissions)}
	return s.flush()
}

// Update changes what a role grants. Its name stays: accounts refer to it.
func (s *RoleStore) Update(name Role, p Permissions) error {
	if _, ok := builtIn(name); ok {
		return ErrRoleBuiltIn
	}
	if !validPermissions(p) {
		return ErrRolePermissions
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.roles[roleKey(name)]
	if !ok || r.Name != name {
		return ErrRoleNotFound
	}
	r.Permissions = cleanPermissions(p)
	s.roles[roleKey(name)] = r
	return s.flush()
}

func (s *RoleStore) Delete(name Role) error {
	if _, ok := builtIn(name); ok {
		return ErrRoleBuiltIn
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.roles[roleKey(name)]
	if !ok || r.Name != name {
		return ErrRoleNotFound
	}
	delete(s.roles, roleKey(name))
	return s.flush()
}

// flush writes the roles made here. The caller holds the lock.
func (s *RoleStore) flush() error {
	if s.path == "" {
		return nil
	}
	stored := make([]RoleDef, 0, len(s.roles))
	for _, r := range s.roles {
		stored = append(stored, r)
	}
	sort.Slice(stored, func(i, j int) bool { return roleKey(stored[i].Name) < roleKey(stored[j].Name) })
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
