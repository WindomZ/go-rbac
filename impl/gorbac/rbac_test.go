package gorbac

import (
	. "github.com/WindomZ/go-rbac"
	"testing"
)

var (
	rA = NewRole("role-a")
	pA = NewPermission("permission-a")
	rB = NewRole("role-b")
	pB = NewPermission("permission-b")
	rC = NewRole("role-c")
	pC = NewPermission("permission-c")

	rbac *RBAC
)

func assert(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestRbacPrepare(t *testing.T) {
	rbac = New()
	assert(t, rA.Assign(pA))
	assert(t, rB.Assign(pB))
	assert(t, rC.Assign(pC))
}

func TestRbacAdd(t *testing.T) {
	assert(t, rbac.AddRole(rA))
	if err := rbac.AddRole(rA); err != ErrRoleExist {
		t.Error("A role can not be readded")
	}
	assert(t, rbac.AddRole(rB))
	assert(t, rbac.AddRole(rC))
}

func TestRbacGetRemove(t *testing.T) {
	assert(t, rbac.SetParent("role-c", "role-a"))
	assert(t, rbac.SetParent("role-a", "role-b"))
	if r, parents, err := rbac.GetRole("role-a"); err != nil {
		t.Fatal(err)
	} else if r.ID() != "role-a" {
		t.Fatalf("[role-a] does not match %s", r.ID())
	} else if len(parents) != 1 {
		t.Fatal("[role-a] should have one parent")
	}
	assert(t, rbac.RemoveRole("role-a"))
	if _, ok := rbac.roles["role-a"]; ok {
		t.Fatal("Role removing failed")
	}
	if err := rbac.RemoveRole("not-exist"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}
	if r, parents, err := rbac.GetRole("role-a"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	} else if r != nil {
		t.Fatal("The instance of role should be a nil")
	} else if parents != nil {
		t.Fatal("The slice of parents should be a nil")
	}
}

func TestRbacParents(t *testing.T) {
	assert(t, rbac.SetParent("role-c", "role-b"))
	if _, ok := rbac.parents["role-c"]["role-b"]; !ok {
		t.Fatal("Parent binding failed")
	}
	assert(t, rbac.RemoveParent("role-c", "role-b"))
	if _, ok := rbac.parents["role-c"]["role-b"]; ok {
		t.Fatal("Parent unbinding failed")
	}
	if err := rbac.RemoveParent("role-a", "role-b"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}
	if err := rbac.RemoveParent("role-b", "role-a"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}
	if err := rbac.SetParent("role-a", "role-b"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}
	if err := rbac.SetParent("role-c", "role-a"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}
	if err := rbac.SetParents("role-a", []string{"role-b"}); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}
	if err := rbac.SetParents("role-c", []string{"role-a"}); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	}
	assert(t, rbac.SetParents("role-c", []string{"role-b"}))
	if _, ok := rbac.parents["role-c"]["role-b"]; !ok {
		t.Fatal("Parent binding failed")
	}
	if parents, err := rbac.GetParents("role-a"); err != ErrRoleNotExist {
		t.Fatalf("%s needed", ErrRoleNotExist)
	} else if len(parents) != 0 {
		t.Fatal("[role-a] should not have any parent")
	}
	if parents, err := rbac.GetParents("role-b"); err != nil {
		t.Fatal(err)
	} else if len(parents) != 0 {
		t.Fatal("[role-b] should not have any parent")
	}
	if parents, err := rbac.GetParents("role-c"); err != nil {
		t.Fatal(err)
	} else if len(parents) != 1 {
		t.Fatal("[role-c] should have one parent")
	}
}

func TestRbacPermission(t *testing.T) {
	if !rbac.IsGranted("role-c", pC) {
		t.Fatalf("role-c should have %s", pC)
	}
	if rbac.IsAssertGranted("role-c", pC, func(IRBAC, string, IPermission) bool { return false }) {
		t.Fatal("Assertion don't work")
	}
	if !rbac.IsGranted("role-c", pB) {
		t.Fatalf("role-c should have %s which inherits from role-b", pB)
	}

	assert(t, rbac.RemoveParent("role-c", "role-b"))
	if rbac.IsGranted("role-c", pB) {
		t.Fatalf("role-c should not have %s because of the unbinding with role-b", pB)
	}
}

func BenchmarkRbacGranted(b *testing.B) {
	rbac = New()
	rA.Assign(pA)
	rB.Assign(pB)
	rC.Assign(pC)
	rbac.AddRole(rA)
	rbac.AddRole(rB)
	rbac.AddRole(rC)
	for i := 0; i < b.N; i++ {
		rbac.IsGranted("role-a", pA)
	}
}

func BenchmarkRbacNotGranted(b *testing.B) {
	rbac = New()
	rA.Assign(pA)
	rB.Assign(pB)
	rC.Assign(pC)
	rbac.AddRole(rA)
	rbac.AddRole(rB)
	rbac.AddRole(rC)
	for i := 0; i < b.N; i++ {
		rbac.IsGranted("role-a", pB)
	}
}
