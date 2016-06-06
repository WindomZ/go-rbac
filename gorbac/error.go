package gorbac

import "errors"

var (
	ErrRoleNotExist error = errors.New("gorbac: Role does not exist")
	ErrRoleExist          = errors.New("gorbac: Role has already existed")
)
