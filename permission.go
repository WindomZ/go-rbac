package gorbac

type Permission interface {
	ID() string
	Match(Permission) bool
}
