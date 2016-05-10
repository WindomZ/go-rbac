package gorbac

import (
	. "github.com/WindomZ/go-rbac"
	_rbac "github.com/mikespook/gorbac"
)

type Roles map[string]IRole

type Role struct {
	_rbac.StdRole
	permissions Permissions
}

func NewRole(id string) *Role {
	return &Role{
		StdRole:     *_rbac.NewStdRole(id),
		permissions: make(Permissions),
	}
}

// ID returns the role's identity name.
func (role *Role) ID() string {
	return role.StdRole.ID()
}

// Assign a permission to the role.
func (role *Role) Assign(p IPermission) error {
	role.Lock()
	defer role.Unlock()
	role.permissions[p.ID()] = p
	return nil
}

// Permit returns true if the role has specific permission.
func (role *Role) Permit(p IPermission) bool {
	role.RLock()
	defer role.RUnlock()
	for _, rp := range role.permissions {
		if rp.Match(p) {
			return true
		}
	}
	return false
}

// Revoke the specific permission.
func (role *Role) Revoke(p IPermission) error {
	role.Lock()
	defer role.Unlock()
	delete(role.permissions, p.ID())
	return nil
}

// Permissions returns all permissions into a slice.
func (role *Role) Permissions() []IPermission {
	role.RLock()
	defer role.RUnlock()
	result := make([]IPermission, 0, len(role.permissions))
	for _, p := range role.permissions {
		result = append(result, p)
	}
	return result
}
