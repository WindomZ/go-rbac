package gorbac

type AssertionFunc func(RBAC, string, Permission) bool

type RBAC interface {
	SetParents(string, []string) error
	GetParents(string) ([]string, error)
	SetParent(string, string) error
	RemoveParent(string, string) error

	AddRole(Role) error
	RemoveRole(string) error
	GetRole(string) (Role, []string, error)

	IsGranted(string, Permission) bool
	IsAssertGranted(string, Permission, AssertionFunc) bool
}
