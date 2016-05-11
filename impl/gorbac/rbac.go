package gorbac

import (
	. "github.com/WindomZ/go-rbac"
	"sync"
)

var empty = struct{}{}

type RBAC struct {
	mutex       sync.RWMutex
	roles       Roles
	permissions Permissions
	parents     map[string]map[string]struct{}
}

// New returns a RBAC structure.
// The default role structure will be used.
func New() *RBAC {
	return &RBAC{
		roles:       make(Roles),
		permissions: make(Permissions),
		parents:     make(map[string]map[string]struct{}),
	}
}

// SetParents bind `parents` to the role `id`.
// If the role or any of parents is not existing,
// an error will be returned.
func (rbac *RBAC) SetParents(id string, parents []string) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()
	if _, ok := rbac.roles[id]; !ok {
		return ErrRoleNotExist
	}
	for _, parent := range parents {
		if _, ok := rbac.roles[parent]; !ok {
			return ErrRoleNotExist
		}
	}
	if _, ok := rbac.parents[id]; !ok {
		rbac.parents[id] = make(map[string]struct{})
	}
	for _, parent := range parents {
		rbac.parents[id][parent] = empty
	}
	return nil
}

// GetParents return `parents` of the role `id`.
// If the role is not existing, an error will be returned.
// Or the role doesn't have any parents,
// a nil slice will be returned.
func (rbac *RBAC) GetParents(id string) ([]string, error) {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()
	if _, ok := rbac.roles[id]; !ok {
		return nil, ErrRoleNotExist
	}
	ids, ok := rbac.parents[id]
	if !ok {
		return nil, nil
	}
	var parents []string
	for parent := range ids {
		parents = append(parents, parent)
	}
	return parents, nil
}

// SetParent bind the `parent` to the role `id`.
// If the role or the parent is not existing,
// an error will be returned.
func (rbac *RBAC) SetParent(id string, parent string) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()
	if _, ok := rbac.roles[id]; !ok {
		return ErrRoleNotExist
	}
	if _, ok := rbac.roles[parent]; !ok {
		return ErrRoleNotExist
	}
	if _, ok := rbac.parents[id]; !ok {
		rbac.parents[id] = make(map[string]struct{})
	}
	var empty struct{}
	rbac.parents[id][parent] = empty
	return nil
}

// RemoveParent unbind the `parent` with the role `id`.
// If the role or the parent is not existing,
// an error will be returned.
func (rbac *RBAC) RemoveParent(id string, parent string) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()
	if _, ok := rbac.roles[id]; !ok {
		return ErrRoleNotExist
	}
	if _, ok := rbac.roles[parent]; !ok {
		return ErrRoleNotExist
	}
	delete(rbac.parents[id], parent)
	return nil
}

// Add a role `r`.
func (rbac *RBAC) AddRole(r IRole) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()
	if _, ok := rbac.roles[r.ID()]; ok {
		return ErrRoleExist
	}
	rbac.roles[r.ID()] = r
	return nil
}

// Remove the role by `id`.
func (rbac *RBAC) RemoveRole(id string) error {
	rbac.mutex.Lock()
	defer rbac.mutex.Unlock()
	if _, ok := rbac.roles[id]; !ok {
		return ErrRoleNotExist
	}
	delete(rbac.roles, id)
	for rid, parents := range rbac.parents {
		if rid == id {
			delete(rbac.parents, rid)
			continue
		}
		for parent := range parents {
			if parent == id {
				delete(rbac.parents[rid], id)
				break
			}
		}
	}
	return nil
}

// Get the role by `id` and a slice of its parents id.
func (rbac *RBAC) GetRole(id string) (IRole, []string, error) {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()
	r, ok := rbac.roles[id]
	if !ok {
		return nil, nil, ErrRoleNotExist
	}
	var parents []string
	for parent := range rbac.parents[id] {
		parents = append(parents, parent)
	}
	return r, parents, nil
}

// IsGranted tests if the role `id` has IPermission `p`.
func (rbac *RBAC) IsGranted(id string, p IPermission) bool {
	return rbac.IsAssertGranted(id, p, nil)
}

// IsAssertGranted tests if the role `id` has IPermission `p` with the condition `assert`.
func (rbac *RBAC) IsAssertGranted(id string, p IPermission, assert AssertionFunc) bool {
	rbac.mutex.RLock()
	defer rbac.mutex.RUnlock()
	return rbac.isGranted(id, p, assert)
}

func (rbac *RBAC) isGranted(id string, p IPermission, assert AssertionFunc) bool {
	if assert != nil && !assert(rbac, id, p) {
		return false
	}
	return rbac.recursionCheck(id, p)
}

func (rbac *RBAC) recursionCheck(id string, p IPermission) bool {
	if role, ok := rbac.roles[id]; ok {
		if role.Permit(p) {
			return true
		}
		if parents, ok := rbac.parents[id]; ok {
			for pID := range parents {
				if _, ok := rbac.roles[pID]; ok {
					if rbac.recursionCheck(pID, p) {
						return true
					}
				}
			}
		}
	}
	return false
}
