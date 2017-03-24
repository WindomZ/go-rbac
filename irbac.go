package gorbac

type AssertionFunc func(IRBAC, string, IPermission) bool
type AssertionIDFunc func(IRBAC, string, string) bool

type IRBAC interface {
	SetParents(string, []string) error
	GetParents(string) ([]string, error)
	SetParent(string, string) error
	RemoveParent(string, string) error

	AddRole(IRole) error
	RemoveRole(string) error
	GetRole(string) (IRole, []string, error)
	GetRoleOnly(string) (IRole, error)

	IsGranted(string, IPermission) bool
	IsGrantedID(string, string) bool
	IsAssertGranted(string, IPermission, AssertionFunc) bool
	IsAssertGrantedID(string, string, AssertionIDFunc) bool
}
