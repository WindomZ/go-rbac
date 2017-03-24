package gorbac

// _Permission only checks if the Ids are fully matching.
type _Permission struct {
	IDStr string `json:"id"`
}

// ID returns the identity of permission
func (p *_Permission) ID() string {
	return p.IDStr
}

// Match another permission
func (p *_Permission) Match(a Permission) bool {
	return p.MatchID(a.ID())
}

// Match another permission with id
func (p *_Permission) MatchID(id string) bool {
	return p.ID() == id
}
