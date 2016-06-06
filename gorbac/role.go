package gorbac

import (
	. "github.com/WindomZ/go-rbac"
	"sync"
)

type Roles map[string]IRole

type Role struct {
	sync.RWMutex
	IDStr       string `json:"id"`
	permissions Permissions
}

func NewRole(id string) *Role {
	return &Role{
		IDStr:       id,
		permissions: make(Permissions),
	}
}

// ID returns the role's identity name.
func (role *Role) ID() string {
	return role.IDStr
}

// Assign a permission to the role.
func (role *Role) Assign(p IPermission) error {
	if p == nil || len(p.ID()) == 0 {
		return ErrPermissionNoID
	}
	role.Lock()
	defer role.Unlock()
	role.permissions[p.ID()] = p
	return nil
}

// Assign a permission id to the role.
func (role *Role) AssignID(id string) error {
	if len(id) == 0 {
		return ErrPermissionNoID
	}
	return role.Assign(NewPermission(id))
}

// Assign some permissions id to the role with the condition `assert`.
func (role *Role) AssertAssignIDs(ids []string, assert AssertionAssignFunc) {
	if ids == nil || len(ids) == 0 {
		return
	}
	for _, id := range ids {
		p := NewPermission(id)
		if assert != nil && !assert(p) {
			continue
		}
		role.Assign(p)
	}
}

// Permit returns true if the role has specific permission.
func (role *Role) Permit(p IPermission) bool {
	return role.PermitID(p.ID())
}

// Permit returns true if the role has specific permission id.
func (role *Role) PermitID(id string) bool {
	if len(id) == 0 {
		return false
	}
	role.RLock()
	defer role.RUnlock()
	for _, rp := range role.permissions {
		if rp.MatchID(id) {
			return true
		}
	}
	return false
}

// Revoke the specific permission.
func (role *Role) Revoke(p IPermission) error {
	return role.RevokeID(p.ID())
}

// Revoke the specific permission.
func (role *Role) RevokeID(id string) error {
	if len(id) == 0 {
		return nil
	}
	role.Lock()
	defer role.Unlock()
	delete(role.permissions, id)
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

// Permissions returns all permission ids into a slice.
func (role *Role) PermissionIDs() []string {
	role.RLock()
	defer role.RUnlock()
	result := make([]string, 0, len(role.permissions))
	for _, p := range role.permissions {
		result = append(result, p.ID())
	}
	return result
}
