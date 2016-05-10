package gorbac

type AssertionFunc func(IRBAC, string, IPermission) bool

type IRBAC interface {
	SetParents(string, []string) error
	GetParents(string) ([]string, error)
	SetParent(string, string) error
	RemoveParent(string, string) error

	AddRole(IRole) error
	RemoveRole(string) error
	GetRole(string) (IRole, []string, error)

	IsGranted(string, IPermission) bool
	IsAssertGranted(string, IPermission, AssertionFunc) bool
}
