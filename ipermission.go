package gorbac

type Permission interface {
	ID() string
	Match(Permission) bool
	MatchID(string) bool
}

type Permissions map[string]Permission

// NewPermission returns a Permission instance with `id`
func NewPermission(id string) Permission {
	return &_Permission{
		IDStr: id,
	}
}
