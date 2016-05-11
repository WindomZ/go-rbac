package gorbac

import "errors"

var (
	ErrRoleNotExist error = errors.New("Role does not exist")
	ErrRoleExist          = errors.New("Role has already existed")
)
