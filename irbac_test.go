package gorbac

import (
	"github.com/WindomZ/testify/assert"
	"testing"
)

func TestNewRBAC(t *testing.T) {
	assert.NotEmpty(t, NewRBAC())
}
