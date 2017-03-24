package gorbac

type AssertionFunc func(RBAC, string, Permission) bool
type AssertionIDFunc func(RBAC, string, string) bool

type RBAC interface {
	SetParents(string, []string) error
	GetParents(string) ([]string, error)
	SetParent(string, string) error
	RemoveParent(string, string) error

	AddRole(Role) error
	RemoveRole(string) error
	GetRole(string) (Role, []string, error)
	GetRoleOnly(string) (Role, error)

	IsGranted(string, Permission) bool
	IsGrantedID(string, string) bool
	IsAssertGranted(string, Permission, AssertionFunc) bool
	IsAssertGrantedID(string, string, AssertionIDFunc) bool
}

// NewRBAC returns a RBAC structure.
// The default role structure will be used.
func NewRBAC() RBAC {
	return &_RBAC{
		roles:       make(Roles),
		permissions: make(Permissions),
		parents:     make(map[string]map[string]struct{}),
	}
}
