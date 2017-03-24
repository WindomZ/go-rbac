package gorbac

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

type _Role struct {
	sync.RWMutex `json:"-"`
	IDStr        string      `json:"id"`
	TagStr       string      `json:"tag"`
	permissions  Permissions `json:"-"`
}

// ID returns the role's identity name.
func (role *_Role) ID() string {
	return role.IDStr
}

// Tag returns the role's tag.
func (role *_Role) Tag() string {
	return role.TagStr
}

// Assign a permission to the role.
func (role *_Role) Assign(p Permission) error {
	if p == nil || len(p.ID()) == 0 {
		return ErrPermissionNoID
	}
	role.Lock()
	defer role.Unlock()
	role.permissions[p.ID()] = p
	return nil
}

// Assign a permission id to the role.
func (role *_Role) AssignID(id string) error {
	if len(id) == 0 {
		return ErrPermissionNoID
	}
	return role.Assign(NewPermission(id))
}

// Assign some permissions id to the role with the condition `assert`.
func (role *_Role) AssertAssignIDs(ids []string, assert AssertionAssignFunc) {
	if ids == nil || len(ids) == 0 {
		return
	}
	for _, id := range ids {
		p := NewPermission(id)
		if assert != nil && !assert(p.ID()) {
			continue
		}
		role.Assign(p)
	}
}

// Permit returns true if the role has specific permission.
func (role *_Role) Permit(p Permission) bool {
	return role.PermitID(p.ID())
}

// Permit returns true if the role has specific permission id.
func (role *_Role) PermitID(id string) bool {
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
func (role *_Role) Revoke(p Permission) error {
	return role.RevokeID(p.ID())
}

// Revoke the specific permission.
func (role *_Role) RevokeID(id string) error {
	if len(id) == 0 {
		return nil
	}
	role.Lock()
	defer role.Unlock()
	delete(role.permissions, id)
	return nil
}

// Permissions returns all permissions into a slice.
func (role *_Role) Permissions() []Permission {
	role.RLock()
	defer role.RUnlock()
	result := make([]Permission, 0, len(role.permissions))
	for _, p := range role.permissions {
		result = append(result, p)
	}
	return result
}

// Permissions returns all permission ids into a slice.
func (role *_Role) PermissionIDs() []string {
	role.RLock()
	defer role.RUnlock()
	result := make([]string, 0, len(role.permissions))
	for _, p := range role.permissions {
		result = append(result, p.ID())
	}
	return result
}

// Sign returns unique signature by role and key
func (role *_Role) Sign(key string) string {
	h := md5.New()
	h.Write([]byte(fmt.Sprintf("%v#%v#%v", role.ID(), key, strings.Join(role.PermissionIDs(), ""))))
	return hex.EncodeToString(h.Sum(nil))
}
