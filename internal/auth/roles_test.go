package auth

import (
	"errors"
	"path/filepath"
	"testing"
)

// The two names every stored account carries keep meaning what they meant.
func TestBuiltInRolesAreWhatAdminAndViewerWere(t *testing.T) {
	s := NewRoleStore("")
	admin, ok := s.Get(RoleAdmin)
	if !ok || !admin.BuiltIn {
		t.Fatal("admin is not a built-in role")
	}
	for _, a := range Areas {
		if !admin.Permissions.Can(a, LevelManage) {
			t.Errorf("admin cannot manage %s", a)
		}
	}
	viewer, _ := s.Get(RoleViewer)
	for _, a := range Areas {
		hidden := a == AreaNotifications || a == AreaSystem
		if viewer.Permissions.Can(a, LevelView) == hidden {
			t.Errorf("viewer view on %s = %v", a, !hidden)
		}
		if viewer.Permissions.Can(a, LevelManage) {
			t.Errorf("viewer can manage %s", a)
		}
	}
}

func TestManageIncludesViewAndAMissingAreaIsNone(t *testing.T) {
	p := Permissions{AreaNetwork: LevelManage, AreaEvents: LevelView}
	if !p.Can(AreaNetwork, LevelView) || !p.Can(AreaNetwork, LevelManage) {
		t.Error("manage does not include view")
	}
	if p.Can(AreaEvents, LevelManage) {
		t.Error("view reaches manage")
	}
	if p.Can(AreaSystem, LevelView) {
		t.Error("an area that is not there is not none")
	}
	if !p.Can(AreaSystem, LevelNone) {
		t.Error("none is not reached by none")
	}
}

func TestRoleNames(t *testing.T) {
	s := NewRoleStore("")
	for _, bad := range []string{"", "   ", "a/b", "名稱", "x" + string(make([]byte, 40))} {
		if err := s.Create(RoleDef{Name: Role(bad)}); !errors.Is(err, ErrRoleName) {
			t.Errorf("Create(%q) = %v, want ErrRoleName", bad, err)
		}
	}
	if err := s.Create(RoleDef{Name: "Event Watcher"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Unique without regard to case, and the built-in names are taken.
	for _, taken := range []string{"event watcher", "EVENT WATCHER", "Admin", "viewer"} {
		if err := s.Create(RoleDef{Name: Role(taken)}); !errors.Is(err, ErrRoleExists) {
			t.Errorf("Create(%q) = %v, want ErrRoleExists", taken, err)
		}
	}
	// An account's role name is matched as it was stored.
	if _, ok := s.Get("event watcher"); ok {
		t.Error("a role answered to a name in another case")
	}
	if _, ok := s.Get("Admin"); ok {
		t.Error("the built-in admin answered to another case")
	}
}

func TestRolePermissionsAreChecked(t *testing.T) {
	s := NewRoleStore("")
	if err := s.Create(RoleDef{Name: "a", Permissions: Permissions{"billing": LevelView}}); !errors.Is(err, ErrRolePermissions) {
		t.Errorf("an unknown area = %v", err)
	}
	if err := s.Create(RoleDef{Name: "a", Permissions: Permissions{AreaEvents: "owner"}}); !errors.Is(err, ErrRolePermissions) {
		t.Errorf("an unknown level = %v", err)
	}
}

func TestBuiltInRolesCannotBeChanged(t *testing.T) {
	s := NewRoleStore("")
	if err := s.Update(RoleViewer, all(LevelManage)); !errors.Is(err, ErrRoleBuiltIn) {
		t.Errorf("Update = %v", err)
	}
	if err := s.Delete(RoleAdmin); !errors.Is(err, ErrRoleBuiltIn) {
		t.Errorf("Delete = %v", err)
	}
}

func TestRolesSurviveAReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roles.json")
	s := NewRoleStore(path)
	if err := s.Create(RoleDef{Name: "netops", Permissions: Permissions{AreaNetwork: LevelManage}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Update("netops", Permissions{AreaNetwork: LevelManage, AreaEvents: LevelView}); err != nil {
		t.Fatal(err)
	}
	r, ok := NewRoleStore(path).Get("netops")
	if !ok || !r.Permissions.Can(AreaNetwork, LevelManage) || !r.Permissions.Can(AreaEvents, LevelView) || r.Permissions.Can(AreaSystem, LevelView) {
		t.Errorf("reloaded role = %+v, %v", r, ok)
	}
	if got := len(NewRoleStore(path).List()); got != 3 {
		t.Errorf("List has %d roles, want the two built in and one made", got)
	}
	if err := s.Delete("netops"); err != nil {
		t.Fatal(err)
	}
	if _, ok := NewRoleStore(path).Get("netops"); ok {
		t.Error("a deleted role came back")
	}
}
